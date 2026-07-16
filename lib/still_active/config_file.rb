# frozen_string_literal: true

require "yaml"
require_relative "suppressions"
require_relative "../helpers/constraint_helper"
require_relative "../helpers/vulnerability_helper"

module StillActive
  # Loads a committed .still_active.yml and applies it to the config as the layer
  # below env vars and CLI flags (CLI flag > env var > config file > default).
  # Mirrors the policy flags (gates, thresholds, output, alternatives, scope)
  # and the granular suppression list; deliberately NOT secrets (tokens) or
  # invocation-specific paths (--gemfile/--gems/--baseline/output paths), which
  # stay CLI/env-only so a committed file never carries a credential.
  module ConfigFile
    FILENAME = ".still_active.yml"
    BUNDLER_AUDIT_FILE = ".bundler-audit.yml"

    extend self

    def load(dir: Dir.pwd)
      path = File.join(dir, FILENAME)
      return {} unless File.file?(path)

      data = YAML.safe_load_file(path, permitted_classes: [Date, Time])
      return {} if data.nil?

      unless data.is_a?(Hash)
        warn("warning: #{FILENAME} must be a mapping of settings; ignoring it")
        return {}
      end

      data
    rescue Psych::Exception => e
      # Covers a syntax error and a disallowed tag (e.g. !ruby/object); either
      # way the committed file must never take the audit down with it.
      warn("warning: #{FILENAME} could not be loaded (#{e.message}); ignoring it")
      {}
    end

    # Applies data to config and returns an array of warning strings (unknown
    # keys, invalid values, suppression/import problems). Booleans/numbers are
    # passed through as the gate expects them.
    def apply(config, data, base_dir: Dir.pwd)
      warnings = []
      ignore_entries = Array(data["ignore"])

      data.each do |key, value|
        case key
        when "fail_if_critical" then set_boolean(config, :fail_if_critical=, value, key, warnings)
        when "fail_if_warning" then set_boolean(config, :fail_if_warning=, value, key, warnings)
        when "fail_if_poison" then apply_fail_if_poison(config, value, warnings)
        when "fail_if_language_ceiling" then apply_fail_if_language_ceiling(config, value, warnings)
        when "alternatives" then set_boolean(config, :alternatives=, value, key, warnings)
        when "unreleased_commits" then set_boolean(config, :unreleased_commits=, value, key, warnings)
        when "direct_only" then set_boolean(config, :direct_only=, value, key, warnings)
        when "safe_range_end" then set_number(config, :no_warning_range_end=, value, key, warnings)
        when "warning_range_end" then set_number(config, :warning_range_end=, value, key, warnings)
        when "fail_if_outdated" then apply_fail_if_outdated(config, value, warnings)
        when "parallelism" then apply_parallelism(config, value, warnings)
        when "fail_if_vulnerable" then apply_fail_if_vulnerable(config, value, warnings)
        when "output" then apply_output(config, value, warnings)
        when "ignore" then nil # handled below, after imports are gathered
        when "import" then ignore_entries.concat(import_advisories(value, base_dir, warnings))
        else warnings << "#{FILENAME}: unknown setting #{key.inspect}, ignoring it"
        end
      end

      suppressions = Suppressions.from(ignore_entries)
      warnings.concat(suppressions.warnings)
      config.suppressions = suppressions
      warnings
    end

    # Suggests honouring an existing bundler-audit ignore list rather than
    # silently inheriting it. Auto-importing another tool's suppressions would
    # hide vulnerabilities the user only accepted in bundler-audit's context,
    # with no reason/expiry and no explicit opt-in here, the exact over-broad
    # muting this feature exists to replace. So nudge, don't absorb, and only
    # when the vulnerability gate is on (suppression is otherwise moot) and the
    # file isn't already imported. Returns the hint string or nil.
    def import_hint(data, config: StillActive.config, dir: Dir.pwd)
      return unless config.fail_if_vulnerable
      return if Array(data["import"]).include?(BUNDLER_AUDIT_FILE)

      path = File.join(dir, BUNDLER_AUDIT_FILE)
      return unless File.file?(path)

      count = bundler_audit_ignore_count(path)
      return unless count.positive?

      noun = (count == 1) ? "advisory" : "advisories"
      "#{BUNDLER_AUDIT_FILE} lists #{count} accepted #{noun}; add `import: [#{BUNDLER_AUDIT_FILE}]` to #{FILENAME} to honour them in still_active's --fail-if-vulnerable gate too"
    end

    private

    def bundler_audit_ignore_count(path)
      data = YAML.safe_load_file(path, permitted_classes: [Date, Time])
      data.is_a?(Hash) ? Array(data["ignore"]).size : 0
    rescue Psych::Exception
      0
    end

    # A malformed value must warn and leave the default in place, never silently
    # flip a gate off (`!!""` is false) or crash the audit (`false.to_f` raises,
    # since `&.` guards only nil). Validate before assigning, like the gates do.
    def set_boolean(config, setter, value, key, warnings)
      if [true, false].include?(value)
        config.public_send(setter, value)
      else
        warnings << "#{FILENAME}: #{key} must be true or false (got #{value.inspect}), ignoring it"
      end
    end

    def set_number(config, setter, value, key, warnings)
      if value.is_a?(Numeric)
        config.public_send(setter, value.to_f)
      else
        warnings << "#{FILENAME}: #{key} must be a number (got #{value.inspect}), ignoring it"
      end
    end

    def apply_fail_if_outdated(config, value, warnings)
      case value
      when nil, false then config.fail_if_outdated = nil # gate off
      when Numeric then config.fail_if_outdated = value.to_f
      else warnings << "#{FILENAME}: fail_if_outdated must be a number or false (got #{value.inspect}), ignoring it"
      end
    end

    def apply_parallelism(config, value, warnings)
      if value.is_a?(Integer) && value.positive?
        config.parallelism = value
      else
        warnings << "#{FILENAME}: parallelism must be a positive integer (got #{value.inspect}), ignoring it"
      end
    end

    # true/false, or a severity tier (note|warning|critical). Mirrors the CLI
    # flag: bare `true` fails at :warning, a tier sets an explicit threshold.
    def apply_fail_if_poison(config, value, warnings)
      if value == true || value == false
        config.fail_if_poison = value
      elsif ConstraintHelper::SEVERITY.map(&:to_s).include?(value.to_s)
        config.fail_if_poison = value.to_sym
      else
        warnings << "#{FILENAME}: fail_if_poison must be true/false or one of #{ConstraintHelper::SEVERITY.join(", ")} (got #{value.inspect}), ignoring it"
      end
    end

    # true/false, or a severity tier (note|warning|critical). Mirrors the CLI
    # flag: bare `true` fails at :warning, a tier sets an explicit threshold.
    def apply_fail_if_language_ceiling(config, value, warnings)
      if value == true || value == false
        config.fail_if_language_ceiling = value
      elsif ConstraintHelper::SEVERITY.map(&:to_s).include?(value.to_s)
        config.fail_if_language_ceiling = value.to_sym
      else
        warnings << "#{FILENAME}: fail_if_language_ceiling must be true/false or one of #{ConstraintHelper::SEVERITY.join(", ")} (got #{value.inspect}), ignoring it"
      end
    end

    def apply_fail_if_vulnerable(config, value, warnings)
      if value == true || value == false
        config.fail_if_vulnerable = value || nil
      elsif VulnerabilityHelper::SEVERITY_ORDER.include?(value)
        config.fail_if_vulnerable = value
      else
        warnings << "#{FILENAME}: fail_if_vulnerable severity must be one of #{VulnerabilityHelper::SEVERITY_ORDER.join(", ")} (got #{value.inspect}), ignoring it"
      end
    end

    def apply_output(config, value, warnings)
      format = value.to_s.to_sym
      if [:terminal, :markdown, :json].include?(format)
        config.output_format = format
      else
        warnings << "#{FILENAME}: output must be terminal, markdown, or json (got #{value.inspect}), ignoring it"
      end
    end

    # Reads each referenced bundler-audit config and converts its ignore list of
    # advisory ids into advisory-scoped (gem-agnostic) suppression entries, so a
    # team keeps one ignore list instead of two.
    def import_advisories(paths, base_dir, warnings)
      Array(paths).flat_map do |rel|
        path = File.expand_path(rel, base_dir)
        unless File.file?(path)
          warnings << "#{FILENAME}: import target #{rel} not found, skipping it"
          next []
        end

        imported = YAML.safe_load_file(path, permitted_classes: [Date, Time]) || {}
        unless imported.is_a?(Hash)
          warnings << "#{FILENAME}: import target #{rel} is not a mapping, skipping it"
          next []
        end

        Array(imported["ignore"]).map { |advisory| {"advisory" => advisory, "reason" => "imported from #{rel}"} }
      rescue Psych::Exception => e
        warnings << "#{FILENAME}: import target #{rel} could not be loaded (#{e.message}), skipping it"
        []
      end
    end
  end
end
