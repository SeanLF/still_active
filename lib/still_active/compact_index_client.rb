# frozen_string_literal: true

require "cgi"
require "rubygems/resolver"
require "uri"
require_relative "../helpers/http_helper"

module StillActive
  # The RubyGems compact index (`/info/<gem>`), which is what Bundler itself
  # resolves through. It is not built by merging upstream metadata, so it lists
  # the versions actually resolvable from the source even when a member remote (a
  # legacy private gem host) can't answer the metadata endpoint Artifactory
  # prefers (#142).
  #
  # The protocol is generic: any host that serves it (rubygems.org, Artifactory, a
  # direct Contribsys/Gemstash/geminabox source) works here. The caller supplies
  # the source URI and any auth headers, so this stays free of host-specific
  # credential handling.
  module CompactIndexClient
    extend self

    def versions(gem_name:, source_uri:, headers: {})
      base = URI(source_uri.chomp("/"))
      path = "#{base.path}/info/#{CGI.escape(gem_name)}"
      body = HttpHelper.get_text(base, path, headers: headers)
      return [] if body.nil? || body.empty?

      result = parse(body)
      # The parser never raises: a non-index 200 (an auth wall or HTML error page
      # served with status 200) yields no versions instead of an error. Since the
      # compact index is the primary source, a silent empty result would look
      # identical to a clean parse and hide a broken source, so say so and let the
      # caller fall through. A header-only index (every version yanked) is valid
      # and empty, so the "---" marker, not mere emptiness, tells them apart.
      if result.empty? && !compact_index?(body)
        warn("warning: #{base.host} answered /info/#{gem_name} with a 200 that is not a RubyGems " \
          "compact index (an auth wall or error page?); ignoring it and trying other sources")
      end
      result
    end

    private

    def compact_index?(body)
      body.split("\n").include?("---")
    end

    def parse(body)
      entries(body)
        .filter_map { |line| version_hash(line) }
        .group_by { |hash| hash["number"] }
        .map { |_number, rows| platform_independent(rows).except("platform") }
        .sort_by { |hash| Gem::Version.new(hash["number"]) }
        .reverse
    end

    # A version gets one row per built platform, variants first and the
    # platform-independent build last. That last row is the one describing the
    # gem rather than one prebuilt binary: a native gem's variants ship fewer
    # dependencies, since they don't need the toolchain the source build does.
    def platform_independent(rows)
      rows.find { |row| row["platform"].nil? } || rows.first
    end

    # Everything after the `---` header. Artifactory is known to emit blank
    # lines inside its index files (Bundler's own compact index parser carries
    # the same workaround), and a blank line would parse as a nil version.
    def entries(body)
      lines = body.split("\n")
      header = lines.index("---")
      lines = lines[(header + 1)..] if header
      lines.reject { |line| line.strip.empty? }
    end

    def version_hash(line)
      number, platform = gem_parser.parse(line)
      return if number.nil? || !Gem::Version.correct?(number)

      meta = metadata(line)
      {
        "number" => number,
        "platform" => platform,
        "prerelease" => Gem::Version.new(number).prerelease?,
        # Omitted entirely when a version declares no Ruby requirement, where
        # the versions API sends ">= 0". Both mean unconstrained, and the
        # ceiling check reads a missing requirement as "no ceiling".
        "ruby_version" => meta["ruby"],
        "checksum" => meta["checksum"],
        # rubygems.org emits this; Artifactory's generated index does not, which
        # is why a compact-index list still gets dated from the versions API.
        "created_at" => meta["created_at"]
      }
    end

    # The requirements section (everything after "|") is comma-separated
    # `key:value` pairs, with `&` joining multiple constraints on one key. We
    # parse it directly rather than through GemParser: GemParser's colon split
    # changed across RubyGems versions and shreds an ISO-8601 `created_at`, whose
    # value contains colons. Splitting on the FIRST colon keeps the timestamp
    # whole on every version.
    def metadata(line)
      _deps, requirements = line.split("|", 2)
      return {} unless requirements

      requirements.split(",").each_with_object({}) do |pair, meta|
        key, value = pair.split(":", 2)
        meta[key] = value.split("&").join(", ") if value
      end
    end

    # Used only for the leading `version[-platform]` token, which is a stable
    # split across RubyGems versions. Ships with RubyGems since 3.2.3.
    def gem_parser
      @gem_parser ||= Gem::Resolver::APISet::GemParser.new
    end
  end
end
