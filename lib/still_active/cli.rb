# frozen_string_literal: true

require_relative "options"
require_relative "../helpers/bundler_helper"
require_relative "../helpers/emoji_helper"
require_relative "../helpers/markdown_helper"
require_relative "../helpers/version_helper"
require_relative "workflow"

module StillActive
  class CLI
    include VersionHelper

    def run(args)
      options = Options.new.parse!(args)
      if options[:provided_gems]
        StillActive.config.gems.map! { |gem| { name: gem } }
      else
        StillActive.config.gems = BundlerHelper.gemfile_dependencies
      end

      result = Workflow.call
      case StillActive.config.output_format
      when :json
        puts result.to_json
      when :markdown
        puts MarkdownHelper.markdown_table_header_line
        result.keys.sort.each do |name|
          result[name].merge!({
            last_activity_warning_emoj: EmojiHelper.inactive_gem_emoji(result[name]),
            up_to_date_emoji: EmojiHelper.using_latest_emoji(
              using_last_release: VersionHelper.up_to_date?(
                version_used: result[name].dig(:version_used), latest_version: result[name].dig(:latest_version),
              ),
              using_last_pre_release: VersionHelper.up_to_date?(
                version_used: result[name].dig(:version_used), latest_version: result[name].dig(:latest_pre_release_version),
              ),
            ),
          })

          puts MarkdownHelper.markdown_table_body_line(gem_name: name, data: result[name])
        end
      end
    end
  end
end
