# Alternative-gem Leads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** When still_active flags a gem as archived/critical, optionally surface up to 3 maintained Ruby Toolbox category-siblings ("leads, not answers"), ranked by downloads, opt-in behind `--alternatives`, silent on catalog miss.

**Architecture:** Two new best-effort helpers — `CatalogIndex` (fetches + caches a gem→siblings map from the rubytoolbox/catalog tarball) and `AlternativesHelper` (ranks siblings by rubygems downloads). The workflow loads the index once before its async fan-out (mirroring `RubyAdvisoryDb` at `workflow.rb:24`) and, when the flag is on and a gem is `:archived`/`:critical`, writes `result[gem][:alternatives]`. Formatters render that key where it fits; nothing participates in `--fail-if-*`.

**Tech Stack:** Ruby, octokit (existing dep), `gems` gem (existing dep), stdlib `Zlib`/`Gem::Package::TarReader`/`YAML`, RSpec 4 beta, rubocop-shopify.

**Spec:** `docs/superpowers/specs/2026-06-08-alternatives-leads-design.md`

**Conventions:** helpers live in `lib/helpers/`, `extend self` module style. Tests stub boundaries (octokit fetch, `Gems.info`) rather than hitting the network — matching `spec/still_active/workflow_spec.rb`. Run the full suite with `bundle exec rspec` and `bundle exec rubocop` (no path args) before each commit.

---

## File structure

- Create `lib/helpers/catalog_index.rb` — `StillActive::CatalogIndex`: `load -> Hash{gem => [sibling names]} | nil`. Owns fetch, parse, cache, TTL. Best-effort (never raises).
- Create `lib/helpers/alternatives_helper.rb` — `StillActive::AlternativesHelper`: `leads_for(gem_name:, index:, limit: 3) -> [String]`. Owns slug-filtering, bounded download lookups, ranking.
- Modify `lib/still_active/config.rb` — add `:alternatives` accessor (default `false`).
- Modify `lib/still_active/options.rb` — add `--alternatives` flag.
- Modify `lib/still_active/workflow.rb` — load index once, gate, set `:alternatives`.
- Modify `lib/helpers/terminal_helper.rb` — leads sub-line + off-flag hint.
- Modify `lib/helpers/markdown_helper.rb` — leads section + off-flag hint.
- Modify `lib/helpers/sarif_helper.rb` — append leads to SA001/SA002 result messages.
- JSON needs no code change (the result hash is serialized at `cli.rb:60`); covered by a test.
- Tests: `spec/still_active/catalog_index_spec.rb`, `spec/still_active/alternatives_helper_spec.rb`, additions to `workflow_spec.rb`, `terminal_helper_spec.rb`, `markdown_helper_spec.rb`, `sarif_helper_spec.rb`.

---

## Task 1: `CatalogIndex` — parse a tarball into gem→siblings

**Files:**
- Create: `lib/helpers/catalog_index.rb`
- Test: `spec/still_active/catalog_index_spec.rb`

- [ ] **Step 1: Write the failing test for parsing.** Build a tiny gzipped tar in-memory so no network is touched.

```ruby
# spec/still_active/catalog_index_spec.rb
# frozen_string_literal: true

require "stringio"
require "zlib"
require "rubygems/package"

RSpec.describe(StillActive::CatalogIndex) do
  # Build a gzipped tarball shaped like the rubytoolbox/catalog repo.
  def tarball(files)
    io = StringIO.new
    gz = Zlib::GzipWriter.new(io)
    Gem::Package::TarWriter.new(gz) do |tar|
      files.each do |path, body|
        tar.add_file(path, 0o644) { |f| f.write(body) }
      end
    end
    gz.close
    io.string
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
```

- [ ] **Step 2: Run it, verify it fails.**

Run: `bundle exec rspec spec/still_active/catalog_index_spec.rb -e build_index`
Expected: FAIL — `uninitialized constant StillActive::CatalogIndex`.

- [ ] **Step 3: Implement parsing (and the file skeleton).**

```ruby
# lib/helpers/catalog_index.rb
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
    MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024 # the catalog is ~50KB; cap to avoid surprises

    # Parse a gzipped catalog tarball into { gem_name => [sibling gem names] }.
    def build_index(tar_gz_blob)
      categories = []
      reader = Gem::Package::TarReader.new(Zlib::GzipReader.new(StringIO.new(tar_gz_blob)))
      reader.each do |entry|
        next unless entry.file?
        next unless entry.full_name =~ %r{/catalog/.+\.ya?ml$}
        next if File.basename(entry.full_name) == "_meta.yml"

        data = YAML.safe_load(entry.read)
        next unless data.is_a?(Hash) && data["projects"].is_a?(Array)

        categories << data["projects"].map { |p| p.to_s.split("/").last }
      end

      build_siblings(categories)
    end

    private

    def build_siblings(categories)
      siblings = Hash.new { |hash, key| hash[key] = [] }
      categories.each do |members|
        members.each do |gem_name|
          siblings[gem_name].concat(members - [gem_name])
        end
      end
      siblings.transform_values(&:uniq)
    end
  end
end
```

- [ ] **Step 4: Run it, verify it passes.**

Run: `bundle exec rspec spec/still_active/catalog_index_spec.rb -e build_index`
Expected: PASS (2 expectations).

- [ ] **Step 5: Commit.**

```bash
git add lib/helpers/catalog_index.rb spec/still_active/catalog_index_spec.rb
git commit -m "feat: parse rubytoolbox catalog tarball into gem->siblings index"
```

---

## Task 2: `CatalogIndex.load` — fetch + cache + TTL + best-effort

**Files:**
- Modify: `lib/helpers/catalog_index.rb`
- Test: `spec/still_active/catalog_index_spec.rb`

- [ ] **Step 1: Write the failing tests.** Stub the fetch and the cache path so nothing touches the network or real disk.

```ruby
# add inside RSpec.describe(StillActive::CatalogIndex) in catalog_index_spec.rb
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
      expect(described_class).not_to(receive(:download))
      expect(described_class.load["paperclip"]).to(eq(["shrine"]))
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
```

Add `require "tmpdir"` and `require "fileutils"` at the top of the spec.

- [ ] **Step 2: Run, verify failures.**

Run: `bundle exec rspec spec/still_active/catalog_index_spec.rb -e .load`
Expected: FAIL — `load` undefined / `cache_path` undefined.

- [ ] **Step 3: Implement load/cache/download.** Add to `catalog_index.rb` (public `load`, private helpers):

```ruby
    # Returns { gem => [siblings] } or nil. Never raises.
    def load
      cached = read_cache
      return cached if cached

      blob = download
      index = build_index(blob)
      write_cache(index)
      index
    rescue StandardError => e
      warn("still_active: could not load Ruby Toolbox catalog for alternatives (#{e.class}); skipping leads")
      nil
    end
```

```ruby
    # add to the private section
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
      URI.open(url) { |io| io.read(MAX_DOWNLOAD_BYTES) } # rubocop:disable Security/Open
    end
```

Note: `URI.open` follows the codeload redirect octokit's `archive_link` returns. The `download` and `build_index` boundaries are what tests stub.

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/catalog_index_spec.rb`
Expected: PASS (all).

- [ ] **Step 5: Commit.**

```bash
git add lib/helpers/catalog_index.rb spec/still_active/catalog_index_spec.rb
git commit -m "feat: CatalogIndex.load with disk cache, TTL, and best-effort fetch"
```

---

## Task 3: `AlternativesHelper` — rank siblings by downloads, top 3

**Files:**
- Create: `lib/helpers/alternatives_helper.rb`
- Test: `spec/still_active/alternatives_helper_spec.rb`

- [ ] **Step 1: Write the failing tests.**

```ruby
# spec/still_active/alternatives_helper_spec.rb
# frozen_string_literal: true

RSpec.describe(StillActive::AlternativesHelper) do
  describe(".leads_for") do
    let(:index) { { "cancan" => ["pundit", "cancancan", "rabarber", "with/slug"] } }

    before do
      allow(Gems).to(receive(:info).with("pundit").and_return({ "downloads" => 102 }))
      allow(Gems).to(receive(:info).with("cancancan").and_return({ "downloads" => 90 }))
      allow(Gems).to(receive(:info).with("rabarber").and_return({ "downloads" => 1 }))
    end

    it("returns the top 3 siblings by downloads, slug entries dropped") do
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "cancancan", "rabarber"]))
    end

    it("returns [] when the gem has no catalog entry") do
      expect(described_class.leads_for(gem_name: "unknown", index: index)).to(eq([]))
    end

    it("returns [] when the index is nil") do
      expect(described_class.leads_for(gem_name: "cancan", index: nil)).to(eq([]))
    end

    it("drops siblings whose download lookup fails, rather than the whole list") do
      allow(Gems).to(receive(:info).with("cancancan").and_raise(StandardError))
      expect(described_class.leads_for(gem_name: "cancan", index: index))
        .to(eq(["pundit", "rabarber"]))
    end
  end
end
```

- [ ] **Step 2: Run, verify failure.**

Run: `bundle exec rspec spec/still_active/alternatives_helper_spec.rb`
Expected: FAIL — `uninitialized constant StillActive::AlternativesHelper`.

- [ ] **Step 3: Implement.**

```ruby
# lib/helpers/alternatives_helper.rb
# frozen_string_literal: true

require "gems"

module StillActive
  # Turns a gem's catalog siblings into ranked "leads" — the most-downloaded
  # still-published alternatives. Best-effort: a failed lookup drops that
  # candidate, never the feature.
  module AlternativesHelper
    extend self

    MAX_SIBLINGS_CONSIDERED = 40 # bound the download lookups for huge categories
    DEFAULT_LIMIT = 3

    def leads_for(gem_name:, index:, limit: DEFAULT_LIMIT)
      return [] if index.nil?

      siblings = (index[gem_name] || [])
        .reject { |name| name.include?("/") } # github-slug-only projects can't be ranked by rubygems downloads
        .first(MAX_SIBLINGS_CONSIDERED)
      return [] if siblings.empty?

      siblings
        .filter_map { |name| [name, downloads(name)] if downloads(name) }
        .sort_by { |_name, count| -count }
        .first(limit)
        .map(&:first)
    end

    private

    def downloads(gem_name)
      info = Gems.info(gem_name)
      info && info["downloads"]
    rescue StandardError
      nil
    end
  end
end
```

Note: `downloads` is called twice per sibling in `filter_map` for clarity; if profiling shows it matters, memoize. For ~40 siblings it is negligible relative to the HTTP cost — keep it simple.

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/alternatives_helper_spec.rb`
Expected: PASS (4 expectations).

Wait — `filter_map` calling `downloads` twice means the stub `.and_raise` on the second call also raises in the guard. Re-check the failing-lookup test: `downloads("cancancan")` raises -> rescued -> nil both times -> dropped. Correct. PASS.

- [ ] **Step 5: Commit.**

```bash
git add lib/helpers/alternatives_helper.rb spec/still_active/alternatives_helper_spec.rb
git commit -m "feat: AlternativesHelper ranks catalog siblings by downloads"
```

---

## Task 4: Config + `--alternatives` flag

**Files:**
- Modify: `lib/still_active/config.rb`
- Modify: `lib/still_active/options.rb`
- Test: `spec/still_active/config_spec.rb`, `spec/still_active/options_spec.rb`

- [ ] **Step 1: Write failing tests.**

```ruby
# spec/still_active/config_spec.rb — add
  it("defaults alternatives to false") do
    expect(described_class.new.alternatives).to(be(false))
  end
```

```ruby
# spec/still_active/options_spec.rb — add (match the existing parse pattern in this file)
  it("enables alternatives with --alternatives") do
    described_class.new.parse!(["--alternatives"])
    expect(StillActive.config.alternatives).to(be(true))
  end
```

- [ ] **Step 2: Run, verify failure.**

Run: `bundle exec rspec spec/still_active/config_spec.rb spec/still_active/options_spec.rb -e alternatives`
Expected: FAIL — `NoMethodError: undefined method 'alternatives'`.

- [ ] **Step 3: Implement.**

In `config.rb`, add `:alternatives` to the `attr_accessor` list (keep it alphabetical-ish with the others) and initialize it:

```ruby
    # in attr_accessor list, add:
      :alternatives,
```
```ruby
    # in initialize, with the other booleans:
      @alternatives = false
```

In `options.rb`, add to `add_output_options` (after the `--json` line):

```ruby
      opts.on("--alternatives", "Suggest maintained alternatives (Ruby Toolbox leads) for archived/critical gems") do
        StillActive.config { |config| config.alternatives = true }
      end
```

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/config_spec.rb spec/still_active/options_spec.rb`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add lib/still_active/config.rb lib/still_active/options.rb spec/still_active/config_spec.rb spec/still_active/options_spec.rb
git commit -m "feat: add --alternatives opt-in flag"
```

---

## Task 5: Workflow integration — load index, gate, set `:alternatives`

**Files:**
- Modify: `lib/still_active/workflow.rb`
- Test: `spec/still_active/workflow_spec.rb`

- [ ] **Step 1: Write the failing tests.** Add a context to `workflow_spec.rb`. Reuse the file's existing stubbing style (it stubs `Gems`, `DepsDevClient`, and `described_class.last_commit_date`/`repo_archived`).

```ruby
  context("when --alternatives is enabled and a gem is archived") do
    before do
      StillActive.config.gems = [{ name: "paperclip", version: "6.0.0" }]
      StillActive.config.alternatives = true
      allow(Gems).to(receive(:versions).with("paperclip").and_return([
        { "number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z", "licenses" => ["MIT"] },
      ]))
      allow(Gems).to(receive(:info).with("paperclip").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
      allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
      allow(described_class).to(receive_messages(repo_archived: true, last_commit_date: nil))
      allow(StillActive::CatalogIndex).to(receive(:load).and_return({ "paperclip" => ["shrine", "carrierwave"] }))
      allow(StillActive::AlternativesHelper).to(receive(:leads_for).and_return(["shrine", "carrierwave"]))
    end

    it("sets alternatives on the archived gem") do
      expect(result["paperclip"][:alternatives]).to(eq(["shrine", "carrierwave"]))
    end
  end

  context("when --alternatives is disabled") do
    before do
      StillActive.config.gems = [{ name: "paperclip", version: "6.0.0" }]
      StillActive.config.alternatives = false
      allow(Gems).to(receive(:versions).with("paperclip").and_return([
        { "number" => "6.0.0", "prerelease" => false, "created_at" => "2018-01-01T00:00:00Z" },
      ]))
      allow(Gems).to(receive(:info).with("paperclip").and_return({ "homepage_uri" => nil, "source_code_uri" => nil }))
      allow(StillActive::DepsDevClient).to(receive_messages(version_info: nil, project_scorecard: nil))
      allow(described_class).to(receive_messages(repo_archived: true, last_commit_date: nil))
    end

    it("does not load the catalog or set alternatives") do
      expect(StillActive::CatalogIndex).not_to(receive(:load))
      expect(result["paperclip"]).not_to(have_key(:alternatives))
    end
  end
```

- [ ] **Step 2: Run, verify failure.**

Run: `bundle exec rspec spec/still_active/workflow_spec.rb -e alternatives`
Expected: FAIL — `:alternatives` key absent / `CatalogIndex` referenced before it exists in workflow.

- [ ] **Step 3: Implement.** Three edits in `workflow.rb`.

(a) Require the helpers at the top, next to the existing requires (e.g. after the `ruby_advisory_db` require near line 7):

```ruby
require_relative "../helpers/catalog_index"
require_relative "../helpers/alternatives_helper"
require_relative "../helpers/activity_helper"
```

(b) In `call`, load the index once next to `advisory_db = RubyAdvisoryDb.load` (~line 24):

```ruby
        advisory_db = RubyAdvisoryDb.load
        catalog = StillActive.config.alternatives ? CatalogIndex.load : nil
```

Thread `catalog:` through the `gem_info(...)` call in the fan-out (add the keyword):

```ruby
            gem_info(
              gem_name: gem[:name],
              result_object: hash,
              gem_version: gem[:version],
              source_type: gem[:source_type] || :rubygems,
              source_uri: gem[:source_uri],
              advisory_db: advisory_db,
              catalog: catalog,
            )
```

(c) Add `catalog: nil` to the `gem_info` signature, and after the per-source branch populates the result, attach leads:

```ruby
    def gem_info(gem_name:, result_object:, gem_version: nil, source_type: :rubygems, source_uri: nil, advisory_db: nil, catalog: nil)
      result_object[gem_name] = { source_type: source_type }
      result_object[gem_name][:version_used] = gem_version if gem_version

      case source_type
      when :path, :git
        gem_info_non_rubygems(gem_name: gem_name, gem_version: gem_version, result_object: result_object, source_uri: source_uri, advisory_db: advisory_db)
      else
        gem_info_rubygems(
          gem_name: gem_name,
          gem_version: gem_version,
          result_object: result_object,
          source_uri: source_uri,
          advisory_db: advisory_db,
        )
      end

      attach_alternatives(gem_name: gem_name, result_object: result_object, catalog: catalog)
    end
```

Add the private helper:

```ruby
    def attach_alternatives(gem_name:, result_object:, catalog:)
      return if catalog.nil?
      return unless [:archived, :critical].include?(ActivityHelper.activity_level(result_object[gem_name]))

      leads = AlternativesHelper.leads_for(gem_name: gem_name, index: catalog)
      result_object[gem_name][:alternatives] = leads unless leads.empty?
    end
```

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/workflow_spec.rb`
Expected: PASS (whole file green, including the two new contexts).

- [ ] **Step 5: Commit.**

```bash
git add lib/still_active/workflow.rb spec/still_active/workflow_spec.rb
git commit -m "feat: attach ranked alternatives to archived/critical gems when --alternatives"
```

---

## Task 6: JSON output carries `:alternatives` (test only)

**Files:**
- Test: `spec/still_active/cli_spec.rb` (or wherever JSON rendering is covered)

- [ ] **Step 1: Write the failing test.** Confirm the key survives serialization (`cli.rb:60` does `puts output.to_json`).

```ruby
  it("includes alternatives in JSON output when present") do
    result = { "paperclip" => { source_type: :rubygems, alternatives: ["shrine", "carrierwave"] } }
    json = JSON.parse(result.to_json)
    expect(json.dig("paperclip", "alternatives")).to(eq(["shrine", "carrierwave"]))
  end
```

- [ ] **Step 2: Run, verify it passes immediately** (serialization is free — this is a guard test, not a code change).

Run: `bundle exec rspec spec/still_active/cli_spec.rb -e "alternatives in JSON"`
Expected: PASS.

- [ ] **Step 3: (no implementation needed.)**

- [ ] **Step 4: (covered by Step 2.)**

- [ ] **Step 5: Commit.**

```bash
git add spec/still_active/cli_spec.rb
git commit -m "test: lock alternatives into JSON output"
```

---

## Task 7: Terminal output — leads sub-line + off-flag hint

**Files:**
- Modify: `lib/helpers/terminal_helper.rb`
- Test: `spec/still_active/terminal_helper_spec.rb`

- [ ] **Step 1: Write failing tests.**

```ruby
  it("prints a leads sub-line under a gem with alternatives") do
    result = { "paperclip" => { source_type: :rubygems, archived: true, alternatives: ["shrine", "carrierwave"] } }
    out = described_class.render(result)
    expect(out).to(include("leads (Ruby Toolbox): shrine · carrierwave"))
  end

  it("prints a discoverability hint for an archived gem when alternatives are off") do
    StillActive.config.alternatives = false
    result = { "paperclip" => { source_type: :rubygems, archived: true } }
    out = described_class.render(result)
    expect(out).to(include("--alternatives"))
  end

  it("prints nothing extra for a healthy gem") do
    result = { "rails" => { source_type: :rubygems, last_commit_date: Time.now } }
    out = described_class.render(result)
    expect(out).not_to(include("leads (Ruby Toolbox)"))
    expect(out).not_to(include("--alternatives"))
  end
```

- [ ] **Step 2: Run, verify failure.**

Run: `bundle exec rspec spec/still_active/terminal_helper_spec.rb -e leads`
Expected: FAIL — strings absent.

- [ ] **Step 3: Implement.** Change the `rows.each` rendering loop in `render` to also emit the per-gem extra line. Replace:

```ruby
      rows.each { |row| lines << row_line(row, widths) }
```

with an index-aware loop so each row keeps its gem name/data:

```ruby
      names = result.keys.sort
      names.each_with_index do |name, i|
        lines << row_line(rows[i], widths)
        extra = alternatives_line(name, result[name])
        lines << extra if extra
      end
```

Add the private helper:

```ruby
    def alternatives_line(name, data)
      level = ActivityHelper.activity_level(data)
      return unless [:archived, :critical].include?(level)

      leads = data[:alternatives]
      if leads && !leads.empty?
        AnsiHelper.dim("  ↳ leads (Ruby Toolbox): #{leads.join(" · ")} — verify fit")
      elsif !StillActive.config.alternatives
        AnsiHelper.dim("  ↳ run with --alternatives for maintained replacements")
      end
    end
```

(`rows` is already `result.keys.sort.map { ... }`, so `rows[i]` aligns with `names[i]`.)

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/terminal_helper_spec.rb`
Expected: PASS (file green).

- [ ] **Step 5: Commit.**

```bash
git add lib/helpers/terminal_helper.rb spec/still_active/terminal_helper_spec.rb
git commit -m "feat: terminal leads sub-line and --alternatives hint"
```

---

## Task 8: Markdown + SARIF output

**Files:**
- Modify: `lib/helpers/markdown_helper.rb`, `lib/helpers/sarif_helper.rb`
- Test: `spec/still_active/markdown_helper_spec.rb`, `spec/still_active/sarif_helper_spec.rb`

- [ ] **Step 1: Write failing tests.**

```ruby
# markdown_helper_spec.rb — exercise whatever top-level render method the file exposes (e.g. .render).
  it("lists alternatives for flagged gems after the table") do
    result = { "paperclip" => { source_type: :rubygems, archived: true, alternatives: ["shrine", "carrierwave"] } }
    out = described_class.render(result) # use the file's actual public render entrypoint
    expect(out).to(include("**Alternatives**"))
    expect(out).to(include("`paperclip`: shrine, carrierwave"))
  end
```

```ruby
# sarif_helper_spec.rb
  it("appends alternatives to the archived-gem result message") do
    result = { "paperclip" => { source_type: :rubygems, version_used: "6.0.0", archived: true, alternatives: ["shrine", "carrierwave"] } }
    sarif = JSON.parse(described_class.render(result: result, ruby_info: nil, lockfile_path: "Gemfile.lock", tool_version: "x"))
    msg = sarif.dig("runs", 0, "results").find { |r| r["ruleId"] == "SA001" }.dig("message", "text")
    expect(msg).to(include("Consider: shrine, carrierwave"))
  end
```

- [ ] **Step 2: Run, verify failure.**

Run: `bundle exec rspec spec/still_active/markdown_helper_spec.rb spec/still_active/sarif_helper_spec.rb -e Alternatives -e alternatives`
Expected: FAIL.

- [ ] **Step 3: Implement.**

SARIF (`sarif_helper.rb`, in `gem_results`): append leads to the SA001 and SA002 messages. Replace the SA001 line:

```ruby
      if data[:archived]
        out << result("SA001", name, "#{name} #{version}: upstream repository is archived#{repo_suffix(data)}.#{alternatives_suffix(data)}", location)
      end
```

and the SA002 `result(...)` call similarly (append `#{alternatives_suffix(data)}` to its message string). Add the private helper:

```ruby
    def alternatives_suffix(data)
      leads = data[:alternatives]
      return "" if leads.nil? || leads.empty?

      " Consider: #{leads.join(", ")}."
    end
```

Markdown (`markdown_helper.rb`): add a render-time section after the table. In the public render method (the one that assembles the table — confirm its name in the file; e.g. `render`), after building the table string, append:

```ruby
    def alternatives_section(result)
      flagged = result.select do |_name, data|
        data[:alternatives] && !data[:alternatives].empty?
      end
      return "" if flagged.empty?

      lines = ["", "**Alternatives** (Ruby Toolbox leads — verify fit):"]
      flagged.each { |name, data| lines << "- `#{name}`: #{data[:alternatives].join(", ")}" }
      lines.join("\n")
    end
```

and concatenate `alternatives_section(result)` onto the rendered markdown output. (If markdown has no single `render`, append the section wherever `cli.rb` assembles the markdown body — check `cli.rb` around the `:markdown` branch.)

- [ ] **Step 4: Run, verify pass.**

Run: `bundle exec rspec spec/still_active/markdown_helper_spec.rb spec/still_active/sarif_helper_spec.rb`
Expected: PASS.

- [ ] **Step 5: Commit.**

```bash
git add lib/helpers/markdown_helper.rb lib/helpers/sarif_helper.rb spec/still_active/markdown_helper_spec.rb spec/still_active/sarif_helper_spec.rb
git commit -m "feat: render alternatives in markdown and SARIF output"
```

---

## Task 9: Full-suite + lint + README

**Files:**
- Modify: `README.md`
- Test: whole suite

- [ ] **Step 1: Document the flag.** Add `--alternatives` to the CLI options section of `README.md` (match the existing option list formatting) and one sentence under Usage describing the leads-not-answers behaviour and that it is opt-in.

- [ ] **Step 2: Run the full suite across seeds.**

Run: `bundle exec rspec` then `bundle exec rspec --seed 1` then `--seed 42`
Expected: all green (the suite is order-independent; keep it that way).

- [ ] **Step 3: Run rubocop (no path args).**

Run: `bundle exec rubocop`
Expected: no offenses. Fix any (the new files must follow rubocop-shopify; note `# rubocop:disable Security/Open` on the `URI.open` line in `download`).

- [ ] **Step 4: Verify floors still hold.**

Run: `BUNDLE_GEMFILE=Gemfile.floors bundle exec rspec` (no new runtime deps were added, so this should stay green).
Expected: green.

- [ ] **Step 5: Commit.**

```bash
git add README.md
git commit -m "docs: document --alternatives flag"
```

---

## Self-review (completed during planning)

- **Spec coverage:** CatalogIndex fetch/cache/TTL/best-effort (Tasks 1-2); AlternativesHelper downloads-ranking/top-3/slug-filter/silent (Task 3); opt-in flag + hint (Tasks 4, 7); workflow gate on `:archived/:critical` (Task 5); output in terminal/markdown/JSON/SARIF, not CycloneDX (Tasks 6-8); README (Task 9). All spec sections map to a task.
- **Deviation from spec, intentional:** unit tests stub the fetch/`Gems.info` boundaries instead of using VCR cassettes for a binary tarball — simpler and matches `workflow_spec.rb`'s existing style. The verified real fetch path is exercised manually via `scratch/poc_fetch.rb`.
- **Type/name consistency:** `CatalogIndex.load -> Hash|nil`; `AlternativesHelper.leads_for(gem_name:, index:, limit:)`; `result[gem][:alternatives] -> [String]`; `attach_alternatives`/`alternatives_line`/`alternatives_suffix`/`alternatives_section` are the only new method names, each defined in its task.
- **Open confirmation for the implementer:** the exact public render entrypoints of `markdown_helper.rb` and the `:markdown` branch in `cli.rb` — Task 8 Step 3 says to confirm the method name in-file before wiring (the file was read at plan time; `markdown_table_*` build rows, and the assembled body is concatenated in `cli.rb`).
