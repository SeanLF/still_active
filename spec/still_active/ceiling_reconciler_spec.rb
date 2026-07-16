# frozen_string_literal: true

require_relative "../../lib/still_active/ceiling_reconciler"

RSpec.describe(StillActive::CeilingReconciler) do
  describe ".reconcile_ceiling_with_poison" do
    it "drops a ceiling's fixed_by_upgrade when the same tree poisons that package below the fix" do
      result = {
        "foo" => {language_ceiling: {requirement: "< 3.3", eol_forced: true, severity: :critical, fixed_by_upgrade: true}},
        "bar" => {constraints: [{dependency: "foo", requirement: "< 2.0", dep_latest: "2.0.0", majors_behind: 1, kind: :ceiling}]}
      }
      described_class.reconcile_ceiling_with_poison(result)
      expect(result["foo"][:language_ceiling][:fixed_by_upgrade]).to(be(false))
      expect(result["foo"][:language_ceiling][:upgrade_blocked]).to(be(true))
    end

    it "leaves fixed_by_upgrade true when nothing caps that package" do
      result = {"foo" => {language_ceiling: {fixed_by_upgrade: true}}}
      described_class.reconcile_ceiling_with_poison(result)
      expect(result["foo"][:language_ceiling][:fixed_by_upgrade]).to(be(true))
      expect(result["foo"][:language_ceiling]).not_to(have_key(:upgrade_blocked))
    end

    it "matches on the package :name for SBOM-keyed results (key is ecosystem/name@version)" do
      # SBOM results are keyed by "pypi/foo@1.2.0" but poison names the bare dep,
      # so the correlation must use data[:name], not the compound key.
      result = {
        "pypi/foo@1.2.0" => {ecosystem: :pypi, name: "foo", language_ceiling: {requirement: "<3.10", eol_forced: true, fixed_by_upgrade: true}},
        "pypi/bar@0.1.0" => {ecosystem: :pypi, name: "bar", constraints: [{dependency: "foo", requirement: "<1.0", dep_latest: "2.0.0", majors_behind: 2, kind: :ceiling}]}
      }
      described_class.reconcile_ceiling_with_poison(result)
      expect(result["pypi/foo@1.2.0"][:language_ceiling][:fixed_by_upgrade]).to(be(false))
      expect(result["pypi/foo@1.2.0"][:language_ceiling][:upgrade_blocked]).to(be(true))
    end

    it "does not let a poison-cap in ONE ecosystem block a same-named package's ceiling in ANOTHER" do
      # Both rubygems and pypi are flat-resolution, so a mixed SBOM can hold a
      # rubygems "foo" (poison-capped) and a pypi "foo" (with a ceiling). The
      # rubygems cap must not flip the pypi package's fixed_by_upgrade.
      result = {
        "pypi/foo@1.2.0" => {ecosystem: :pypi, name: "foo", language_ceiling: {fixed_by_upgrade: true}},
        "rubygems/foo@0.1.0" => {ecosystem: :rubygems, name: "foo", constraints: [{dependency: "foo", requirement: "<1.0", dep_latest: "2.0.0", majors_behind: 2, kind: :ceiling}]}
      }
      described_class.reconcile_ceiling_with_poison(result)
      expect(result["pypi/foo@1.2.0"][:language_ceiling][:fixed_by_upgrade]).to(be(true))
      expect(result["pypi/foo@1.2.0"][:language_ceiling]).not_to(have_key(:upgrade_blocked))
    end
  end
end
