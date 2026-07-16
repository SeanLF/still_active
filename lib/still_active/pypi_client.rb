# frozen_string_literal: true

require_relative "../helpers/http_helper"
require_relative "version"

module StillActive
  # The authoritative source for a PyPI release's declared Python constraint,
  # used by the cross-ecosystem language-runtime ceiling. `requires_python` is
  # set once per release and enforced by pip as a hard install wall (a real
  # resolver refuses an incompatible interpreter), so still_active reads it from
  # PyPI's release-level `info.requires_python` rather than a per-file wheel value
  # or deps.dev (which does not carry the field). pypi.org is a public source,
  # queried with no credentials.
  #
  # Best-effort like every other network entry point: an unindexed version,
  # schema drift, or a transport failure degrades to nil (no ceiling), never a
  # raise that could abort the per-package audit.
  module PypiClient
    extend self

    BASE_URI = URI("https://pypi.org/")
    # Polite identification, matching EcosystemsClient's convention.
    USER_AGENT = "still_active/#{StillActive::VERSION} (+https://github.com/SeanLF/still_active)".freeze

    # The PEP 440 `requires_python` specifier a release declares (e.g.
    # ">=3.8,<3.13"), or nil when the version is unreadable or declares none.
    # PyPI renders an unset constraint as an empty string; normalize it to nil so
    # callers get a single "no constraint" signal.
    def requires_python(name:, version:)
      return if name.nil? || version.nil?

      path = "/pypi/#{encode(name)}/#{encode(version)}/json"
      body = HttpHelper.get_json(BASE_URI, path, headers: {"User-Agent" => USER_AGENT})
      return unless body.is_a?(Hash)

      # Guard the nested read: a non-Hash `info` (schema drift) would make
      # Hash#dig raise TypeError, which -- since this is the LAST enrichment in
      # EcosystemLens#assess -- would propagate to the per-package rescue and
      # discard the package's already-computed vuln/poison/staleness findings.
      # Best-effort must never demote the core audit; degrade to nil.
      info = body["info"]
      return unless info.is_a?(Hash)

      value = info["requires_python"]
      return unless value.is_a?(String) && !value.strip.empty?

      value
    end

    private

    def encode(segment)
      URI.encode_www_form_component(segment)
    end
  end
end
