# frozen_string_literal: true

require "stringio"
require "zlib"
require "rubygems/package"
require_relative "../../lib/helpers/catalog_index"

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
      "catalog-main/catalog/Auth/_meta.yml" => "name: Auth\n",
    )
  end

  describe(".build_index") do
    it("maps each gem to its co-category siblings, excluding itself and _meta") do
      index = described_class.build_index(catalog)
      expect(index["paperclip"]).to(contain_exactly("shrine", "carrierwave"))
      expect(index["cancan"]).to(contain_exactly("pundit"))
      expect(index).not_to(have_key("_meta"))
    end
  end
end
