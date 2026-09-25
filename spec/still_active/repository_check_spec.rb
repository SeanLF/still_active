# frozen_string_literal: true

RSpec.describe(StillActive::RepositoryCheck) do
  # A missing key means the repository step never ran (an assessment that
  # raised): the gates and the summary have to agree it failed.
  it("reads a missing or unrecognised check as failed, in the gate and the tally alike") do
    [{}, {repository_check: "bogus"}].each do |data|
      expect(described_class.failed?(data)).to(be(true))
      expect(described_class.unanswered?(data)).to(be(true))
    end
    expect(described_class.tally([{}, {repository_check: "bogus"}, {repository_check: "unknowable"}])).to(eq(answered: 0, failed: 2, unknowable: 1, not_applicable: 0))
  end
end
