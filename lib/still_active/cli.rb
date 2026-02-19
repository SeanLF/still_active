# frozen_string_literal: true

require_relative "options"
require_relative "../helpers/activity_helper"
require_relative "../helpers/bundler_helper"
require_relative "../helpers/emoji_helper"
require_relative "../helpers/markdown_helper"
require_relative "../helpers/terminal_helper"
require_relative "../helpers/version_helper"
require_relative "workflow"

module StillActive
  class CLI
    def run(args)
      options = Options.new.parse!(args)
      if options[:provided_gems]
        StillActive.config.gems.map! { |gem| { name: gem } }
      else
        StillActive.config.gems = BundlerHelper.gemfile_dependencies
      end

      result = Workflow.call

      case resolve_format
      when :json
        puts result.to_json
      when :terminal
        puts TerminalHelper.render(result)
      when :markdown
        render_markdown(result)
      end

      check_exit_status(result)
    end

    private

    def resolve_format
      format = StillActive.config.output_format
      return format unless format == :auto

      $stdout.tty? ? :terminal : :json
    end

    def render_markdown(result)
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
    end

    def check_exit_status(result)
      config = StillActive.config
      return unless config.fail_if_critical || config.fail_if_warning

      ignored = config.ignored_gems
      checked = result.reject { |name, _| ignored.include?(name) }
      levels = checked.each_value.map { |gem_data| ActivityHelper.activity_level(gem_data) }

      exit(1) if config.fail_if_warning && levels.intersect?([:stale, :critical, :archived])
      exit(1) if config.fail_if_critical && levels.intersect?([:critical, :archived])
    end
  end
end
