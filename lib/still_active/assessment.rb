# frozen_string_literal: true

module StillActive
  # One dependency's assessment, as every consumer (status, gates, renderers)
  # reads it. Both audit paths assemble a hash field by field, then build this
  # once every pass over it is done, so what reaches a consumer is complete:
  #
  # - Every field is declared here. An unknown one, when building or reading, is
  #   an error in the specs (strict, set by spec_helper) and a warning in a
  #   user's run, where it's dropped: the build happens after every lookup is
  #   paid for, and one stray field mustn't cost the whole audit's output.
  # - The answers that decide "clean or unknown" are never missing. A hash that
  #   never had its advisories looked up is vulnerabilities_checked: false; one
  #   that never reached its repository is repository_check: "failed". A missing
  #   key used to read as "fine" wherever a consumer tested it for false.
  #
  # to_h gives back only the fields the path set (and the decided answers), so
  # the JSON output keeps its shape: a field absent from it stays absent.
  class Assessment < Data.define(
    :ecosystem, :name, :purl, :source_type, :production, :direct, :dependency_path,
    :version_used, :version_used_release_date, :version_yanked, :version_unresolved,
    :latest_version, :latest_version_release_date,
    :latest_pre_release_version, :latest_pre_release_version_release_date,
    :up_to_date, :libyear, :license, :deprecated, :deprecation_reason,
    :repository_url, :repository_source, :repository_check, :last_commit_date, :archived,
    :ruby_gems_url, :unreleased_commits, :scorecard_score, :scorecard_maintained,
    :vulnerability_count, :vulnerabilities_checked, :vulnerabilities,
    :constraints, :poison, :poison_severity, :poison_security_relevant, :poison_below_fix,
    :language_ceiling, :alternatives,
    :given
  )
    FIELDS = (members - [:given]).freeze
    REPOSITORY_CHECKS = ["answered", "failed", "unknowable", "not_applicable"].freeze

    class << self
      attr_accessor :strict

      def from(hash)
        unknown = hash.keys - FIELDS
        unless unknown.empty?
          unknown_field!(ArgumentError, "unknown assessment field(s): #{unknown.join(", ")}")
          hash = hash.slice(*FIELDS)
        end

        # Only an explicit answer counts: missing, nil or unrecognised is not one.
        decided = {
          vulnerabilities_checked: hash[:vulnerabilities_checked] == true,
          repository_check: REPOSITORY_CHECKS.include?(hash[:repository_check]) ? hash[:repository_check] : "failed"
        }
        values = FIELDS.to_h { [_1, nil] }.merge(hash, decided)
        new(**values, given: (hash.keys | decided.keys).freeze)
      end

      def unknown_field!(error, message)
        raise error, message if strict

        warn("warning: #{message} (an internal bug; please report it)")
      end
    end

    def [](field)
      unless FIELDS.include?(field)
        self.class.unknown_field!(KeyError, "unknown assessment field: #{field.inspect}")
        return
      end

      public_send(field)
    end

    def dig(field, *rest)
      value = self[field]
      (rest.empty? || value.nil?) ? value : value.dig(*rest)
    end

    # Whether the path set this field (it may still be nil).
    def key?(field) = given.include?(field)
    alias_method :has_key?, :key?

    def to_h = given.to_h { [_1, public_send(_1)] }

    def to_json(*args) = to_h.to_json(*args)

    def with(**changes) = super(**changes, given: (given | changes.keys).freeze)
  end
end
