# frozen_string_literal: true

require_relative "options"
require_relative "../helpers/activity_helper"
require_relative "../helpers/bundler_helper"
require_relative "../helpers/emoji_helper"
require_relative "../helpers/markdown_helper"
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

      case resolve_format
      when :json
        output = { gems: result }
        output[:ruby] = ruby_info if ruby_info
        puts output.to_json
      when :terminal
        puts TerminalHelper.render(result, ruby_info: ruby_info)
      when :markdown
        render_markdown(result, ruby_info: ruby_info)
      end

      check_exit_status(result)
    end

    private

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
