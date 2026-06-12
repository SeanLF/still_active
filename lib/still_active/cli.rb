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
require_relative "../helpers/terminal_helper"
require_relative "../helpers/version_helper"
require_relative "../helpers/vulnerability_helper"
require_relative "workflow"

module StillActive
  class CLI
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
      unless options[:provided_gems]
        begin
          StillActive.config.gems = BundlerHelper.gemfile_dependencies
        rescue MissingLockfileError => e
          $stderr.puts("error: #{e.message}")
          exit(2)
        end
      end

      warn_output_flag_conflicts(options)

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
            schema_version: 1,
            tool: { name: "still_active", version: StillActive::VERSION },
            generated_at: Time.now.utc.iso8601,
            # Surface the derived verdict so a machine/LLM consumer reads it
            # directly instead of re-deriving it from the raw dates.
            gems: result.transform_values { |data| data.merge(activity_level: ActivityHelper.activity_level(data)) },
          }
          output[:ruby] = ruby_info if ruby_info
          output[:pr_context] = pr_context if pr_context
          puts output.to_json
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
      if ruby_info
        puts ""
        puts MarkdownHelper.ruby_line(ruby_info)
      end
    end

    def check_exit_status(result)
      config = StillActive.config
      return unless config.fail_if_critical || config.fail_if_warning || config.fail_if_vulnerable || config.fail_if_outdated

      exit(1) if result.any? { |name, data| gate_failed?(name, data, config) }
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
      return false unless data[:vulnerability_count]&.positive?

      live = Array(data[:vulnerabilities]).reject do |vuln|
        suppressions.suppressed?(gem: name, signal: :vulnerability, advisory: vuln[:id], aliases: Array(vuln[:aliases]))
      end
      return false if live.empty?

      setting == true || VulnerabilityHelper.severity_at_or_above?(live, setting)
    end

    def failed_outdated?(name, data, config, suppressions)
      threshold = config.fail_if_outdated
      return false unless threshold
      return false if suppressions.suppressed?(gem: name, signal: :libyear)

      data[:libyear] && data[:libyear] > threshold
    end
  end
end
