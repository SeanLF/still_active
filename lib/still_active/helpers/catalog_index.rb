# frozen_string_literal: true

require "stringio"
require "zlib"
require "rubygems/package"
require "yaml"
require "json"
require "open-uri"

module StillActive
  # Optional source of "alternative gem" leads: the rubytoolbox/catalog repo
  # (MIT) mapped to gem -> co-category siblings. Fetched once and cached; every
  # path is best-effort, returning nil/empty so a miss just means no leads.
  module CatalogIndex
    extend self

    REPO = "rubytoolbox/catalog"
    CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
    MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024 # the catalog is ~50 KB; cap to avoid surprises

    # Returns { gem => [siblings] } or nil. Never raises.
    def load
      cached = read_cache
      return cached if cached

      blob = download
      index = build_index(blob)
      write_cache(index)
      index
    rescue => e
      warn("still_active: could not load Ruby Toolbox catalog for alternatives (#{e.class}); skipping leads")
      nil
    end

    # Parse a gzipped catalog tarball into { gem_name => [sibling gem names] }.
    def build_index(tar_gz_blob)
      categories = []

      reader = Gem::Package::TarReader.new(Zlib::GzipReader.new(StringIO.new(tar_gz_blob)))
      reader.each do |entry|
        next unless entry.file?
        next unless entry.full_name.match?(%r{/catalog/.+\.ya?ml$})
        next if File.basename(entry.full_name) == "_meta.yml"

        data = YAML.safe_load(entry.read)
        next unless data.is_a?(Hash) && data["projects"].is_a?(Array)

        categories << data["projects"].map { |p| p.to_s.split("/").last }
      end

      build_siblings(categories)
    end

    private

    def cache_path
      base = ENV["XDG_CACHE_HOME"]
      base = File.join(Dir.home, ".cache") if base.nil? || base.empty?
      File.join(base, "still_active", "catalog-siblings.json")
    end

    def read_cache
      path = cache_path
      return unless File.exist?(path)
      return if Time.now - File.mtime(path) > CACHE_TTL_SECONDS

      JSON.parse(File.read(path))
    rescue JSON::ParserError
      nil
    end

    def write_cache(index)
      path = cache_path
      require "fileutils"
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, JSON.dump(index))
    rescue SystemCallError
      nil # an unwritable cache dir must not break the feature
    end

    def download
      url = StillActive.config.github_client.archive_link(REPO, format: "tarball", ref: "main")
      # URI(url).open (not URI.open/Kernel#open) so a "|cmd" string can never be
      # treated as a shell command — the URL is a constant-repo archive link, but
      # this keeps the open path injection-proof regardless.
      URI.parse(url).open { |io| io.read(MAX_DOWNLOAD_BYTES) }
    end

    def build_siblings(categories)
      siblings = Hash.new { |h, k| h[k] = [] }

      categories.each do |members|
        members.each do |gem_name|
          siblings[gem_name].concat(members - [gem_name])
        end
      end

      siblings.transform_values(&:uniq)
    end
  end
end
