# frozen_string_literal: true

require "json"
require "prism"

# Cross-path field parity: still_active assesses dependencies through two
# independent paths, the native Bundler audit (Workflow) and the cross-ecosystem
# SBOM audit (EcosystemLens + SbomWorkflow), and each builds its own dependency
# hash. Nothing in the code forces them to agree, so a field added to one path
# has repeatedly had to be noticed by hand and ported later (libyear, up_to_date,
# the language ceiling, the SARIF rule wording).
#
# These specs derive each path's field set from the source of truth for that path
# and compare both against one declared registry, so the divergence is a red test
# rather than a discovery months later. Adding a field to either path fails here
# until it is classified, and classifying it as shared fails until it actually
# exists on both sides.
#
# The two sources of truth are deliberately different, because the paths are:
#
#   native: docs/still_active.schema.json. The published contract, `additionalProperties:
#           false`, already validated against real output by the exhaustive conformance
#           spec in cli_spec.rb. A native field that is not in the schema is already a
#           failure there, so the schema is authoritative by construction.
#   SBOM:   the source, read directly. The SBOM JSON deliberately publishes no `$schema`
#           (its shape differs: composite keys, an unassessable list, no ruby block), so
#           there is no contract file to read and the code is the only truth available.
#
# Every extractor below fails loudly when it matches nothing. An extractor that
# silently returns an empty set would make every comparison trivially pass, which
# is the one failure mode a drift check must not have.
RSpec.describe("cross-path field parity") do # rubocop:disable RSpec/DescribeClass -- spans two assessment paths and the published schema, not one class
  def root
    File.expand_path("../..", __dir__)
  end

  # Fields both paths emit. A field listed here must appear in the native schema
  # AND in the SBOM path's derived set; if one side drops or never gains it, the
  # comparison specs fail naming it.
  def shared_fields
    %i[
      activity_level
      archived
      constraints
      language_ceiling
      last_commit_date
      latest_version
      latest_version_release_date
      libyear
      license
      poison
      poison_below_fix
      poison_security_relevant
      poison_severity
      repository_url
      scorecard_maintained
      scorecard_score
      status
      up_to_date
      version_used
      version_used_release_date
      vulnerabilities
      vulnerability_count
    ]
  end

  # Native-path-only fields, each with the reason it does not travel. The reason
  # is required (a spec below asserts none is blank) so classifying a field as
  # path-specific costs a sentence of justification rather than being a silent
  # opt-out. "Structural" means the SBOM path cannot honestly supply it;
  # "closeable" means it is a real gap nobody has built yet, which is worth
  # keeping visible rather than filing as settled.
  def native_only_fields
    {
      alternatives: "structural: alternatives come from the Ruby Toolbox catalog, which indexes gems only. " \
        "No cross-ecosystem equivalent has been adopted.",
      dependency_path: "closeable: Bundler resolves the tree, so the native path knows who pulled a gem in. " \
        "CycloneDX carries a dependency graph still_active does not read yet (SbomReader takes the flat component list).",
      direct: "closeable: same as dependency_path. Direct-vs-transitive needs the SBOM's dependency graph, " \
        "which is present in the format but not yet parsed.",
      latest_pre_release_version: "structural: RubyGems exposes every version, so the native path can pick the newest " \
        "pre-release. deps.dev models one default version per package and has no pre-release channel to read.",
      latest_pre_release_version_release_date: "structural: see latest_pre_release_version.",
      ruby_gems_url: "structural: a rubygems.org package page is Ruby-specific by definition.",
      source_type: "structural: Bundler source kinds (rubygems, git, path, private host) are a lockfile concept. " \
        "The SBOM path carries `ecosystem` from the PURL instead, which is the cross-ecosystem analogue.",
      unreleased_commits: "structural: comparing the newest release tag against HEAD needs a forge client per package " \
        "and a token, which the SBOM path deliberately does not require (it degrades to tokenless ecosyste.ms).",
      version_yanked: "structural: reading a version as yanked needs the registry's full version list, which the " \
        "native path has and deps.dev does not expose per package. The SBOM path carries `version_unresolved` " \
        "as the analogous signal (pinned version absent while the package resolves)."
    }
  end

  # SBOM-path-only fields, same rule: each needs a reason.
  def sbom_only_fields
    {
      ecosystem: "structural: the native audit is Ruby by definition, so there is nothing to disambiguate. " \
        "The SBOM path spans seven ecosystems and every finding is identified as ecosystem/name.",
      name: "structural: the native result hash is keyed by bare gem name, so the name is the key. The SBOM result " \
        "is keyed ecosystem/name@version (two versions of one package can coexist in a merged SBOM), " \
        "so the bare name has to be carried as a field.",
      production: "closeable: CycloneDX marks dev-vs-prod scope and still_active reads it. Bundler knows a gem's " \
        "group too, but the native path does not thread it through yet.",
      version_unresolved: "structural: the SBOM analogue of version_yanked. deps.dev cannot confirm the pinned " \
        "version exists while the package does, so the signal is 'unresolved', not the stronger 'yanked'."
    }
  end

  # Keys that exist on a dependency hash mid-run but are consumed before output.
  # They are neither shared nor path-specific output; they are internal. Listed
  # so the derived-set comparison can subtract them explicitly instead of a
  # blanket allowance that would hide a genuinely leaked field.
  def transient_keys
    {
      capped_deps: "internal work-list: the lens records every declared dependency of a dormant package as a " \
        "below-the-fix CANDIDATE, and PoisonSecurityCorrelator deletes the key after promoting the real ones. " \
        "poison_security_correlator_spec asserts it never reaches the JSON."
    }
  end

  # --- extractors -----------------------------------------------------------
  #
  # Each reads a source of truth and fails loudly on a miss rather than returning
  # an empty set. `extract` is the negative control: it is the only place a match
  # count is checked, so no extractor can quietly find nothing.
  def extract(label, matches, minimum)
    if matches.size < minimum
      raise "field extraction for #{label} found #{matches.size} keys (expected at least #{minimum}). " \
        "The source it reads was probably restructured; update the extractor in this spec rather than " \
        "lowering the bound, or this drift check silently stops checking anything."
    end

    matches.map(&:to_sym).uniq.sort
  end

  # The published contract's per-gem property names. Authoritative for the native
  # path: cli_spec's conformance test validates real output against this schema
  # with additionalProperties: false, so a native field missing here already fails.
  def native_fields
    schema = JSON.parse(File.read(File.join(root, "docs", "still_active.schema.json")))
    properties = schema.dig("$defs", "gem", "properties")
    raise "docs/still_active.schema.json has no $defs/gem/properties; the schema layout changed" if properties.nil?

    extract("the published JSON schema", properties.keys, 20)
  end

  def lens_source
    File.read(File.join(root, "lib", "still_active", "ecosystem_lens.rb"))
  end

  def sbom_workflow_source
    File.read(File.join(root, "lib", "still_active", "sbom_workflow.rb"))
  end

  def correlator_source
    File.read(File.join(root, "lib", "still_active", "poison_security_correlator.rb"))
  end

  def cli_source
    File.read(File.join(root, "lib", "still_active", "cli.rb"))
  end

  # Walk a file's AST, yielding every node, so the extractors below can ask
  # structural questions instead of matching text. Reading Ruby with regexes
  # would work today and break on the next reformat: this repo did exactly one
  # of those recently (#152, adopting Standard), and an indentation-anchored
  # pattern would have silently changed meaning. Prism is stdlib on the
  # supported Rubies (1.9.0 on both 3.3 and 4.0), and this spec never ships
  # (the gemspec packages lib/ and bin/ only), so it costs no dependency.
  def each_node(source, &block)
    walk = lambda do |node|
      return unless node.is_a?(Prism::Node)

      block.call(node)
      node.compact_child_nodes.each { |child| walk.call(child) }
    end
    walk.call(Prism.parse(source).value)
  end

  # Every key written onto a hash held in the local variable `name`: the keys of
  # a `name = {...}` literal, plus every `name[:key] =` and `name[:key] ||=`
  # anywhere in the file.
  def keys_written_to(source, name)
    keys = []
    each_node(source) do |node|
      case node
      when Prism::LocalVariableWriteNode
        next unless node.name == name && node.value.is_a?(Prism::HashNode)

        node.value.elements.each do |element|
          keys << element.key.unescaped if element.is_a?(Prism::AssocNode) && element.key.is_a?(Prism::SymbolNode)
        end
      when Prism::CallNode, Prism::IndexOrWriteNode
        # `h[:k] = v` parses as a call to :[]= ; `h[:k] ||= v` is its own node.
        next if node.is_a?(Prism::CallNode) && node.name != :[]=
        next unless node.receiver.is_a?(Prism::LocalVariableReadNode) && node.receiver.name == name

        argument = node.arguments&.arguments&.first
        keys << argument.unescaped if argument.is_a?(Prism::SymbolNode)
      end
    end
    keys
  end

  # The symbol arguments of every `receiver.method_name(...)` call in a file,
  # for the two places a field set is expressed as call arguments rather than
  # as writes: `dep.slice(:production)` and `data.merge(activity_level:, ...)`.
  def symbol_arguments_of(source, receiver_name, method_name)
    keys = []
    each_node(source) do |node|
      next unless node.is_a?(Prism::CallNode) && node.name == method_name
      next unless node.receiver.is_a?(Prism::LocalVariableReadNode) && node.receiver.name == receiver_name

      node.arguments&.arguments&.each do |argument|
        case argument
        when Prism::SymbolNode
          keys << argument.unescaped
        when Prism::KeywordHashNode, Prism::HashNode
          argument.elements.each do |element|
            keys << element.key.unescaped if element.is_a?(Prism::AssocNode) && element.key.is_a?(Prism::SymbolNode)
          end
        end
      end
    end
    keys
  end

  # EcosystemLens.assess builds one hash literal and then attaches conditional
  # fields to it. attach_constraints, attach_language_ceiling and friends all
  # live in ecosystem_lens.rb, so this one file is the lens's whole surface.
  def lens_fields
    extract("EcosystemLens", keys_written_to(lens_source, :gem_data), 18)
  end

  # SbomWorkflow copies SBOM-sourced keys onto the assessment via `dep.slice(...)`.
  def sbom_workflow_fields
    extract("SbomWorkflow", symbol_arguments_of(sbom_workflow_source, :dep, :slice), 1)
  end

  # PoisonSecurityCorrelator runs on BOTH paths and writes onto the dependency
  # hash (`data[:key] =`), so whatever it sets is shared by construction. Nested
  # writes (`constraint[:...]`, `ceiling[:...]`) are fields of a nested object,
  # not of the dependency, and are excluded because the receiver is pinned to `data`.
  def correlator_fields
    extract("PoisonSecurityCorrelator", keys_written_to(correlator_source, :data), 3)
  end

  # emit_sbom_json derives two more fields onto each dependency at render time.
  def sbom_render_fields
    extract("emit_sbom_json", symbol_arguments_of(cli_source, :data, :merge), 2)
  end

  # Everything the SBOM path puts on a dependency that reaches the JSON output.
  def sbom_fields
    (lens_fields + sbom_workflow_fields + correlator_fields + sbom_render_fields).uniq.sort - transient_keys.keys
  end

  # --- the registry itself --------------------------------------------------

  it("classifies every field exactly once") do
    buckets = {
      shared: shared_fields,
      native_only: native_only_fields.keys,
      sbom_only: sbom_only_fields.keys,
      transient: transient_keys.keys
    }

    duplicates = buckets.values.flatten.tally.select { |_, count| count > 1 }.keys
    expect(duplicates).to(
      be_empty,
      "these fields appear in more than one bucket, so the registry contradicts itself: #{duplicates.join(", ")}"
    )
  end

  it("gives every path-specific field a reason") do
    blank = native_only_fields.merge(sbom_only_fields).merge(transient_keys).select { |_, reason| reason.to_s.strip.empty? }
    expect(blank.keys).to(
      be_empty,
      "a field is only allowed to be path-specific with a stated reason; these have none: #{blank.keys.join(", ")}"
    )
  end

  # --- the parity comparisons ----------------------------------------------

  it("the native path emits exactly the shared fields plus its declared native-only fields") do
    expected = (shared_fields + native_only_fields.keys).sort

    missing = expected - native_fields
    unclassified = native_fields - expected

    expect(unclassified).to(
      be_empty,
      "these fields are in docs/still_active.schema.json but not in this spec's registry: #{unclassified.join(", ")}. " \
        "Add each to shared_fields (and implement it on the SBOM path), or to native_only_fields with a reason."
    )
    expect(missing).to(
      be_empty,
      "the registry claims the native path emits these, but they are absent from the published schema: #{missing.join(", ")}."
    )
  end

  it("the SBOM path emits exactly the shared fields plus its declared SBOM-only fields") do
    expected = (shared_fields + sbom_only_fields.keys).sort

    missing = expected - sbom_fields
    unclassified = sbom_fields - expected

    expect(unclassified).to(
      be_empty,
      "these fields are written by the SBOM path but not in this spec's registry: #{unclassified.join(", ")}. " \
        "Add each to shared_fields (and implement it on the native path), or to sbom_only_fields with a reason."
    )
    expect(missing).to(
      be_empty,
      "the registry claims the SBOM path emits these, but nothing writes them: #{missing.join(", ")}. " \
        "If a shared field was only ever built on the native side, that is the parity gap this spec exists to catch."
    )
  end

  # The static extractors above read four files; a field merged in from somewhere
  # else entirely would be invisible to them. This runs the real lens against
  # stubbed HTTP and asserts every key it actually produces is accounted for, so
  # the instrument is checked against live output rather than trusted on its own.
  describe("a real EcosystemLens run") do
    before do
      StillActive.reset
      allow(StillActive::EcosystemsClient).to(receive(:declared_dependencies).and_return([]))

      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/.+/versions/.+})
        .to_return(
          status: 200,
          headers: {"Content-Type" => "application/json"},
          body: {"advisoryKeys" => [], "links" => [{"label" => "SOURCE_REPO", "url" => "https://github.com/expressjs/express"}], "publishedAt" => "2026-01-01T00:00:00Z"}.to_json
        )
      stub_request(:get, %r{api\.deps\.dev/v3alpha/systems/[^/]+/packages/[^/]+\z})
        .to_return(
          status: 200,
          headers: {"Content-Type" => "application/json"},
          body: {"versions" => [{"versionKey" => {"version" => "9.9.9"}, "isDefault" => true, "publishedAt" => "2026-06-01T00:00:00Z"}]}.to_json
        )
      stub_request(:get, %r{api\.deps\.dev/v3alpha/projects/})
        .to_return(
          status: 200,
          headers: {"Content-Type" => "application/json"},
          body: {"scorecard" => {"overallScore" => 6.5, "date" => "2026-01-01", "checks" => [{"name" => "Maintained", "score" => 9}]}}.to_json
        )
      stub_request(:get, %r{repos\.ecosyste\.ms/api/v1/hosts/GitHub/repositories/})
        .to_return(status: 200, headers: {"Content-Type" => "application/json"}, body: {"archived" => false, "pushed_at" => "2026-01-01T00:00:00Z"}.to_json)
    end

    it("produces no key the registry does not account for") do
      result = StillActive::EcosystemLens.assess(ecosystem: :npm, name: "express", version: "5.2.1")

      # Sanity-check the harness before trusting its verdict: an assess call that
      # returned an empty hash would make the subset assertion below pass for the
      # wrong reason.
      expect(result.keys.size).to(be >= 10, "the stubbed lens run produced almost nothing (#{result.keys.inspect}); the stubs no longer match")

      accounted = shared_fields + sbom_only_fields.keys + transient_keys.keys
      expect(result.keys - accounted).to(
        be_empty,
        "a real lens run produced keys the registry does not know about: #{(result.keys - accounted).join(", ")}. " \
          "The static extractors in this spec did not see them, so both the registry and the extractors need updating."
      )
    end
  end
end
