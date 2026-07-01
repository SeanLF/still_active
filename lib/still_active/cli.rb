# frozen_string_literal: true

require_relative "options"
require_relative "config_file"
require_relative "diff"
require_relative "../helpers/activity_helper"
require_relative "../helpers/bot_context"
require_relative "../helpers/bundler_helper"
require_relative "../helpers/cyclonedx_helper"
require_relative "../helpers/diff_markdown_helper"
require_relative "../helpers/emoji_helper"
require_relative "../helpers/markdown_helper"
require_relative "../helpers/sarif_helper"
require_relative "../helpers/status_helper"
require_relative "../helpers/summary_helper"
require_relative "../helpers/terminal_helper"
require_relative "../helpers/version_helper"
require_relative "../helpers/vulnerability_helper"
require_relative "sbom_reader"
require_relative "sbom_workflow"
require_relative "workflow"

module StillActive
  class CLI
    # The committed JSON Schema for the --json output. Emitted as `$schema` so
    # the output is self-describing and a consumer can validate it.
    SCHEMA_URL = "https://raw.githubusercontent.com/SeanLF/still_active/main/docs/still_active.schema.json"

    def run(args)
      # Apply the committed .still_active.yml first so CLI flags (parsed next)
      # win over it: CLI flag > env var > config file > default.
      config_data = ConfigFile.load
      ConfigFile.apply(StillActive.config, config_data).each { |warning| $stderr.puts("warning: #{warning}") }
      options = Options.new.parse!(args)
      # After CLI flags resolve, nudge (don't auto-inherit) an un-imported
      # bundler-audit ignore list when the vulnerability gate is on.
      hint = ConfigFile.import_hint(config_data)
      $stderr.puts("hint: #{hint}") if hint
      # An SBOM audit is cross-ecosystem: it runs the deps.dev/ecosyste.ms lens
      # over the SBOM's packages, not Bundler over a lockfile. Dispatch before the
      # Bundler resolution below so a Gemfile is never required (or read).
      return run_sbom if options[:provided_sbom]

      unless options[:provided_gems]
        begin
          StillActive.config.gems = BundlerHelper.gemfile_dependencies
        rescue MissingLockfileError => e
          $stderr.puts("error: #{e.message}")
          exit(2)
        end
      end

      warn_output_flag_conflicts(options)
      warn_stale_suppressions

      result = if $stderr.tty?
        Workflow.call { |done, total| $stderr.print("\rChecking #{done}/#{total} gems...") }
      else
        Workflow.call
      end
      $stderr.print("\r\e[K") if $stderr.tty?

      ruby_info = Workflow.ruby_freshness
      pr_context = BotContext.detect

      if (baseline_path = StillActive.config.baseline_path)
        emit_diff(result, ruby_info, baseline_path, pr_context)
      elsif (sarif_path = StillActive.config.sarif_path)
        emit_sarif(result, ruby_info, sarif_path)
      elsif (cyclonedx_path = StillActive.config.cyclonedx_path)
        emit_cyclonedx(result, ruby_info, cyclonedx_path)
      else
        case resolve_format
        when :json
          output = {
            "$schema": SCHEMA_URL,
            schema_version: 1,
            tool: { name: "still_active", version: StillActive::VERSION },
            generated_at: Time.now.utc.iso8601,
            # A one-object digest of the audit's posture, so a machine/LLM
            # consumer reads the headline counts without iterating every gem.
            summary: SummaryHelper.summarize(result, ruby_info: ruby_info),
            # Surface the derived verdict so a machine/LLM consumer reads it
            # directly instead of re-deriving it from the raw dates.
            gems: result.transform_values do |data|
              data.merge(
                activity_level: ActivityHelper.activity_level(data),
                status: StatusHelper.gem_status(data),
              )
            end,
          }
          output[:ruby] = ruby_info if ruby_info
          output[:pr_context] = pr_context if pr_context
          puts iso8601_times(output).to_json
        when :terminal
          puts BotContext.summary(pr_context) if pr_context
          puts TerminalHelper.render(result, ruby_info: ruby_info)
        when :markdown
          render_markdown(result, ruby_info: ruby_info, pr_context: pr_context)
        end
      end

      check_exit_status(result)
    end

    private

    # The --sbom path: assess a CycloneDX SBOM's packages cross-ecosystem via
    # EcosystemLens, then emit a JSON report shaped like the native audit's but
    # keyed "ecosystem/name@version" and carrying an `unassessable` list of every
    # dep we couldn't assess (reader-level: unsupported ecosystem, no version/PURL;
    # or assessment-level: the lens call raised) rather than silently dropping it.
    def run_sbom
      path = StillActive.config.sbom_path
      require_parseable_sbom(path)
      sbom = SbomReader.parse(path)
      outcome = if $stderr.tty?
        SbomWorkflow.call(sbom) { |done, total| $stderr.print("\rAssessing #{done}/#{total} dependencies...") }
      else
        SbomWorkflow.call(sbom)
      end
      $stderr.print("\r\e[K") if $stderr.tty?

      # A reader-level gap (unsupported ecosystem, no version/PURL) and an
      # assessment-time failure (a raised lens call) both mean "not assessed":
      # surface them together so neither is a silent hole in the reported coverage.
      unassessable = sbom.unassessable + outcome.failures
      emit_sbom_json(outcome.assessed, unassessable)
      warn_unassessable(unassessable)
      check_exit_status(outcome.assessed)
    end

    # SbomReader never raises (a malformed file degrades to an empty result), which
    # is right for the library entrypoint but wrong for the explicit --sbom flag:
    # the user pointed at a file to audit, so a truncated/wrong-format one must
    # error, not flow through to an empty "all clear" report with exit 0.
    def require_parseable_sbom(path)
      doc = JSON.parse(File.read(path))
      return if doc.is_a?(Hash) && doc["components"].is_a?(Array)

      # Matches SbomReader's own parse contract (a `components` array is what it
      # reads). A metadata-only CycloneDX has nothing to audit, so the message
      # names the missing array rather than over-claiming "not CycloneDX".
      $stderr.puts("error: #{path} has no CycloneDX `components` array to audit")
      exit(2)
    rescue JSON::ParserError
      $stderr.puts("error: #{path} is not valid JSON")
      exit(2)
    rescue SystemCallError => e
      # Options checked the path exists, not that it's readable (a permission
      # denial, or a directory). Exit cleanly instead of crashing with a trace.
      $stderr.puts("error: cannot read SBOM file #{path}: #{e.message}")
      exit(2)
    end

    # SBOM output deliberately omits the Ruby audit's `$schema`: the shape differs
    # (composite keys, an unassessable list, no Ruby/PR-context blocks), so it
    # would be a false claim to point at that contract. schema_version stays 1.
    def emit_sbom_json(result, unassessable)
      output = {
        schema_version: 1,
        tool: { name: "still_active", version: StillActive::VERSION },
        generated_at: Time.now.utc.iso8601,
        summary: sbom_summary(result, unassessable),
        dependencies: result.transform_values do |data|
          data.merge(
            activity_level: ActivityHelper.activity_level(data),
            status: StatusHelper.gem_status(data),
          )
        end,
        unassessable:,
      }
      puts iso8601_times(output).to_json
    end

    def sbom_summary(result, unassessable)
      statuses = result.each_value.map { |data| StatusHelper.gem_status(data) }
      {
        total_assessed: result.size,
        unassessable_count: unassessable.size,
        # The single worst per-dependency verdict, so a consumer reads one
        # project-level posture without scanning every dependency.
        status: StatusHelper.project_status(result),
        status_counts: statuses.tally,
      }
    end

    # Unassessable deps are already in the JSON; echo a one-line count to stderr so
    # a human running interactively sees the coverage gap without parsing stdout.
    def warn_unassessable(unassessable)
      return if unassessable.empty?

      noun = unassessable.size == 1 ? "dependency" : "dependencies"
      $stderr.puts("warning: #{unassessable.size} #{noun} could not be assessed " \
        "(unsupported ecosystem, missing version, no package URL, or a lookup failure); see \"unassessable\" in the JSON output")
    end

    # Dates live in the result as real Time objects (the activity/libyear math
    # needs them), but the JSON contract is ISO8601 UTC strings, matching
    # generated_at. Normalize at the serialization boundary only, so the
    # terminal/markdown/SARIF paths keep their Time objects untouched.
    def iso8601_times(value)
      case value
      when Time then value.utc.iso8601
      when Hash then value.transform_values { |v| iso8601_times(v) }
      when Array then value.map { |v| iso8601_times(v) }
      else value
      end
    end

    # A suppression naming a gem that isn't in the resolved dependency set can
    # never fire, so it's dead config worth surfacing (the presence half of
    # suppression rot, alongside the expiry half the entries handle themselves).
    def warn_stale_suppressions
      present = StillActive.config.gems.map { |gem| gem[:name] }
      StillActive.config.suppressions.stale_gem_warnings(present).each do |warning|
        $stderr.puts("warning: #{warning}")
      end
    end

    # The output destinations are mutually exclusive and resolved by precedence
    # (baseline > sarif > cyclonedx > terminal/markdown/json). Warn rather than
    # silently dropping the loser when more than one is set.
    def warn_output_flag_conflicts(options)
      modes = active_output_modes
      if modes.size > 1
        $stderr.puts("warning: multiple output modes set (#{modes.join(", ")}); using #{modes.first}, ignoring #{modes.drop(1).join(", ")}")
      end
      if options[:provided_cyclonedx_version] && StillActive.config.cyclonedx_path.nil?
        $stderr.puts("warning: --cyclonedx-version has no effect without --cyclonedx")
      end
    end

    # In precedence order, so the first entry is the one that actually runs.
    def active_output_modes
      config = StillActive.config
      [
        ("--baseline" if config.baseline_path),
        ("--sarif" if config.sarif_path),
        ("--cyclonedx" if config.cyclonedx_path),
      ].compact
    end

    def emit_sarif(result, ruby_info, sarif_path)
      lockfile = resolve_lockfile_path(StillActive.config.gemfile_path)
      unless File.exist?(lockfile)
        $stderr.puts("error: --sarif requires a lockfile at #{lockfile}")
        exit(2)
      end

      sarif_json = SarifHelper.render(
        result: result,
        ruby_info: ruby_info,
        lockfile_path: lockfile,
        tool_version: StillActive::VERSION,
      )

      if sarif_path == "-"
        puts sarif_json
      else
        File.write(sarif_path, sarif_json)
      end
    end

    def emit_cyclonedx(result, ruby_info, cyclonedx_path)
      sbom = CyclonedxHelper.render(
        result: result,
        ruby_info: ruby_info,
        tool_version: StillActive::VERSION,
        spec_version: StillActive.config.cyclonedx_version,
      )

      if cyclonedx_path == "-"
        puts sbom
      else
        File.write(cyclonedx_path, sbom)
      end
    end

    # Mirrors Bundler's convention: gems.rb -> gems.locked, otherwise <gemfile>.lock.
    def resolve_lockfile_path(gemfile)
      return gemfile.sub(/gems\.rb\z/, "gems.locked") if gemfile.end_with?("gems.rb")

      "#{gemfile}.lock"
    end

    def emit_diff(result, ruby_info, baseline_path, pr_context = nil)
      current = current_snapshot(result, ruby_info)
      baseline = JSON.parse(File.read(baseline_path))
      diff = Diff.call(baseline: baseline, current: current)
      puts "> **#{BotContext.summary(pr_context)}**\n\n" if pr_context
      puts DiffMarkdownHelper.render(diff)
      exit(1) if diff.regressions.any?
    rescue JSON::ParserError => e
      $stderr.puts("error: --baseline file is not valid JSON: #{e.message}")
      exit(2)
    rescue Diff::UnsupportedSchemaError => e
      $stderr.puts("error: #{e.message}")
      exit(2)
    rescue Errno::ENOENT, Errno::EACCES, Errno::EISDIR => e
      $stderr.puts("error: cannot read baseline file: #{e.message}")
      exit(2)
    end

    def current_snapshot(result, ruby_info)
      snapshot = {
        "schema_version" => 1,
        "tool" => { "name" => "still_active", "version" => StillActive::VERSION },
        "generated_at" => Time.now.utc.iso8601,
        "gems" => JSON.parse(result.to_json),
      }
      snapshot["ruby"] = JSON.parse(ruby_info.to_json) if ruby_info
      snapshot
    end

    def resolve_format
      format = StillActive.config.output_format
      return format unless format == :auto

      $stdout.tty? ? :terminal : :json
    end

    def render_markdown(result, ruby_info: nil, pr_context: nil)
      puts "> **#{BotContext.summary(pr_context)}**\n" if pr_context
      puts MarkdownHelper.markdown_table_header_line
      result.keys.sort.each do |name|
        gem_data = result[name]
        gem_data[:last_activity_warning_emoji] = EmojiHelper.inactive_gem_emoji(gem_data)
        gem_data[:up_to_date_emoji] = EmojiHelper.using_latest_emoji(
          using_last_release: VersionHelper.up_to_date(
            version_used: gem_data[:version_used], latest_version: gem_data[:latest_version],
          ),
          using_last_pre_release: VersionHelper.up_to_date(
            version_used: gem_data[:version_used], latest_pre_release_version: gem_data[:latest_pre_release_version],
          ),
        )

        puts MarkdownHelper.markdown_table_body_line(gem_name: name, data: gem_data)
      end
      alternatives = MarkdownHelper.alternatives_section(result)
      puts alternatives unless alternatives.empty?
      transitive = MarkdownHelper.transitive_section(result)
      puts transitive unless transitive.empty?
      if ruby_info
        puts ""
        puts MarkdownHelper.ruby_line(ruby_info)
      end
    end

    def check_exit_status(result)
      config = StillActive.config
      return unless config.fail_if_critical || config.fail_if_warning || config.fail_if_vulnerable || config.fail_if_outdated

      warn_unknown_severity_gate(result, config)
      exit(1) if result.any? { |name, data| gate_failed?(name, data, config) }
    end

    # --fail-if-vulnerable=<threshold> fails closed on an advisory with no CVSS
    # score (it could exceed the threshold; fresh CVEs often lack a score). Say so
    # per gem, so failing a =high gate on an "unknown" severity reads as a
    # deliberate conservative call the user can review and fix or suppress, not a
    # mystery. Only for the thresholded form; bare --fail-if-vulnerable fails on
    # every advisory regardless of severity, so there's nothing to explain.
    def warn_unknown_severity_gate(result, config)
      threshold = config.fail_if_vulnerable
      return unless threshold.is_a?(String)

      suppressions = config.suppressions
      result.each do |name, data|
        next if config.ignored_gems.include?(name)

        unknown = live_advisories(name, data, suppressions).select { |vuln| VulnerabilityHelper.unknown_severity?(vuln) }
        next if unknown.empty?

        ids = unknown.filter_map { |vuln| vuln[:id] }.join(", ")
        labelled = ids.empty? ? "" : " (#{ids})"
        $stderr.puts("warning: #{name} has an advisory of unknown severity#{labelled}; failing --fail-if-vulnerable=#{threshold} because it can't be ruled out below the threshold (review, then fix or suppress it in .still_active.yml)")
      end
    end

    # A gem fails the run when it trips an enabled gate that is neither
    # whole-gem --ignore'd nor covered by a granular .still_active.yml
    # suppression. Each signal is checked independently so accepting one finding
    # (e.g. a single advisory) never blinds the others.
    def gate_failed?(name, data, config)
      return false if config.ignored_gems.include?(name)

      suppressions = config.suppressions
      failed_activity?(name, data, config, suppressions) ||
        failed_vulnerability?(name, data, config, suppressions) ||
        failed_outdated?(name, data, config, suppressions)
    end

    def failed_activity?(name, data, config, suppressions)
      return false unless config.fail_if_warning || config.fail_if_critical
      return false if suppressions.suppressed?(gem: name, signal: :activity)

      level = ActivityHelper.activity_level(data)
      (config.fail_if_warning && [:stale, :critical, :archived].include?(level)) ||
        (config.fail_if_critical && [:critical, :archived].include?(level))
    end

    def failed_vulnerability?(name, data, config, suppressions)
      setting = config.fail_if_vulnerable
      return false unless setting

      # Reason over the live advisory array (not vulnerability_count) so the gate
      # and warn_unknown_severity_gate share one source of truth: a warning that
      # says "failing" can never disagree with whether exit(1) actually fires.
      live = live_advisories(name, data, suppressions)
      return false if live.empty?

      setting == true || VulnerabilityHelper.severity_at_or_above?(live, setting)
    end

    # The gem's advisories minus those an explicit .still_active.yml suppression
    # accepts (by advisory id or alias). Shared by the vulnerability gate and the
    # unknown-severity warning so both reason over the same live set.
    def live_advisories(name, data, suppressions)
      Array(data[:vulnerabilities]).reject do |vuln|
        suppressions.suppressed?(gem: name, signal: :vulnerability, advisory: vuln[:id], aliases: Array(vuln[:aliases]))
      end
    end

    def failed_outdated?(name, data, config, suppressions)
      threshold = config.fail_if_outdated
      return false unless threshold
      return false if suppressions.suppressed?(gem: name, signal: :libyear)

      data[:libyear] && data[:libyear] > threshold
    end
  end
end
