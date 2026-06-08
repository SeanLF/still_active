# frozen_string_literal: true

require "stringio"
require "zlib"
require "rubygems/package"
require "yaml"

module StillActive
  # Optional source of "alternative gem" leads: the rubytoolbox/catalog repo
  # (MIT) mapped to gem -> co-category siblings. Fetched once and cached; every
  # path is best-effort, returning nil/empty so a miss just means no leads.
  module CatalogIndex
    extend self

    REPO = "rubytoolbox/catalog"
    CACHE_TTL_SECONDS = 7 * 24 * 60 * 60
    MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024 # the catalog is ~50 KB; cap to avoid surprises

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
