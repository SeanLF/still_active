# frozen_string_literal: true

module StillActive
  # One dependency's assessment, as every consumer (status, gates, renderers)
  # reads it. Both audit paths assemble a hash field by field, then build this
  # once every pass over it is done, so what reaches a consumer is complete:
  #
  # - Every field is declared here. An unknown one raises, when building and
  #   when reading, so a typo'd or unregistered field is an error, not a nil.
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

    def self.from(hash)
      unknown = hash.keys - FIELDS
      raise ArgumentError, "unknown assessment field(s): #{unknown.join(", ")}" unless unknown.empty?

      decided = {
        vulnerabilities_checked: hash.fetch(:vulnerabilities_checked, false),
        repository_check: hash.fetch(:repository_check, "failed")
      }
      values = FIELDS.to_h { [_1, nil] }.merge(hash, decided)
      new(**values, given: (hash.keys | decided.keys).freeze)
    end

    def [](field)
      raise KeyError, "unknown assessment field: #{field.inspect}" unless FIELDS.include?(field)

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
