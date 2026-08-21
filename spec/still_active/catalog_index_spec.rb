# frozen_string_literal: true

require "stringio"
require "zlib"
require "rubygems/package"
require "tmpdir"
require "fileutils"
require "json"
require_relative "../../lib/still_active/helpers/catalog_index"

RSpec.describe(StillActive::CatalogIndex) do
  # Build a gzipped tarball shaped like the rubytoolbox/catalog repo.
  # TarWriter requires a seekable IO, so we write the tar first then gzip it.
  def tarball(files)
    tar_io = StringIO.new
    Gem::Package::TarWriter.new(tar_io) do |tar|
      files.each do |path, body|
        tar.add_file(path, 0o644) { |f| f.write(body) }
      end
    end
    gz_io = StringIO.new
    Zlib::GzipWriter.wrap(gz_io) { |gz| gz.write(tar_io.string) }
    gz_io.string
  end

  let(:catalog) do
    tarball(
      "catalog-main/catalog/File_Uploads/uploads.yml" =>
        "name: File Uploads\nprojects:\n  - paperclip\n  - shrine\n  - carrierwave\n",
      "catalog-main/catalog/Auth/authorization.yml" =>
        "name: Authorization\nprojects:\n  - cancan\n  - pundit\n",
      "catalog-main/catalog/Auth/_meta.yml" => "name: Auth\n"
    )
  end

  describe(".build_index") do
    it("maps each gem to its co-category siblings, excluding itself and _meta") do
      index = described_class.build_index(catalog)
      expect(index["paperclip"]).to(contain_exactly("shrine", "carrierwave"))
      expect(index["cancan"]).to(contain_exactly("pundit"))
      expect(index).not_to(have_key("_meta"))
    end

    it("indexes owner/repo slug projects by their repo tail, not the raw slug") do
      slug_catalog = tarball(
        "catalog-main/catalog/Web/frameworks.yml" =>
          "name: Frameworks\nprojects:\n  - rails/rails\n  - sinatra\n"
      )
      index = described_class.build_index(slug_catalog)
      expect(index["rails"]).to(contain_exactly("sinatra"))
      expect(index["sinatra"]).to(contain_exactly("rails"))
      expect(index.keys).not_to(include("rails/rails"))
    end
  end

  describe(".load") do
    let(:cache_dir) { Dir.mktmpdir }
    let(:cache_file) { File.join(cache_dir, "catalog-siblings.json") }

    before { allow(described_class).to(receive(:cache_path).and_return(cache_file)) }
    after { FileUtils.remove_entry(cache_dir) }

    it("fetches, builds, caches, and returns the index when cache is cold") do
      allow(described_class).to(receive(:download).and_return(catalog))
      index = described_class.load
      expect(index["paperclip"]).to(contain_exactly("shrine", "carrierwave"))
      expect(File).to(exist(cache_file))
    end

    it("reads a fresh cache without downloading") do
      File.write(cache_file, JSON.dump("paperclip" => ["shrine"]))
      allow(described_class).to(receive(:download))
      result = described_class.load
      expect(result["paperclip"]).to(eq(["shrine"]))
      expect(described_class).not_to(have_received(:download))
    end

    it("re-fetches when the cache is older than the TTL") do
      File.write(cache_file, JSON.dump("paperclip" => ["stale"]))
      File.utime(Time.now - described_class::CACHE_TTL_SECONDS - 60, Time.now - described_class::CACHE_TTL_SECONDS - 60, cache_file)
      allow(described_class).to(receive(:download).and_return(catalog))
      expect(described_class.load["paperclip"]).to(contain_exactly("shrine", "carrierwave"))
    end

    it("returns nil (silent) when the download fails") do
      allow(described_class).to(receive(:download).and_raise(SocketError))
      expect(described_class.load).to(be_nil)
    end
  end
end
