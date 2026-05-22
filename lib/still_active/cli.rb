# frozen_string_literal: true

require_relative "options"
require_relative "diff"
require_relative "../helpers/activity_helper"
require_relative "../helpers/bundler_helper"
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
      options = Options.new.parse!(args)
      unless options[:provided_gems]
        StillActive.config.gems = BundlerHelper.gemfile_dependencies
      end

      result = if $stderr.tty?
        Workflow.call { |done, total| $stderr.print("\rChecking #{done}/#{total} gems...") }
      else
        Workflow.call
      end
      $stderr.print("\r\e[K") if $stderr.tty?

      ruby_info = Workflow.ruby_freshness

      if (baseline_path = StillActive.config.baseline_path)
        emit_diff(result, ruby_info, baseline_path)
      elsif (sarif_path = StillActive.config.sarif_path)
        emit_sarif(result, ruby_info, sarif_path)
      else
        case resolve_format
        when :json
          output = {
            schema_version: 1,
            tool: { name: "still_active", version: StillActive::VERSION },
            generated_at: Time.now.utc.iso8601,
            gems: result,
          }
          output[:ruby] = ruby_info if ruby_info
          puts output.to_json
        when :terminal
          puts TerminalHelper.render(result, ruby_info: ruby_info)
        when :markdown
          render_markdown(result, ruby_info: ruby_info)
        end
      end

      check_exit_status(result)
    end

    private

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

    # Mirrors Bundler's convention: gems.rb -> gems.locked, otherwise <gemfile>.lock.
    def resolve_lockfile_path(gemfile)
      return gemfile.sub(/gems\.rb\z/, "gems.locked") if gemfile.end_with?("gems.rb")

      "#{gemfile}.lock"
    end

    def emit_diff(result, ruby_info, baseline_path)
      current = current_snapshot(result, ruby_info)
      baseline = JSON.parse(File.read(baseline_path))
      diff = Diff.call(baseline: baseline, current: current)
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

    def render_markdown(result, ruby_info: nil)
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
      if ruby_info
        puts ""
        puts MarkdownHelper.ruby_line(ruby_info)
      end
    end

    def check_exit_status(result)
      config = StillActive.config
      return unless config.fail_if_critical || config.fail_if_warning || config.fail_if_vulnerable || config.fail_if_outdated

      ignored = config.ignored_gems
      checked = result.reject { |name, _| ignored.include?(name) }

      if config.fail_if_critical || config.fail_if_warning
        levels = checked.each_value.map { |gem_data| ActivityHelper.activity_level(gem_data) }
        exit(1) if config.fail_if_warning && levels.intersect?([:stale, :critical, :archived])
        exit(1) if config.fail_if_critical && levels.intersect?([:critical, :archived])
      end

      if (vuln_setting = config.fail_if_vulnerable)
        checked.each_value do |d|
          next unless d[:vulnerability_count]&.positive?

          exit(1) if vuln_setting == true
          exit(1) if VulnerabilityHelper.severity_at_or_above?(d[:vulnerabilities], vuln_setting)
        end
      end

      if (threshold = config.fail_if_outdated)
        exit(1) if checked.each_value.any? { |d| d[:libyear] && d[:libyear] > threshold }
      end
    end
  end
end
