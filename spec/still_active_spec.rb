# frozen_string_literal: true

RSpec.describe(StillActive) do
  it "has a version number" do
    expect(StillActive::VERSION).not_to(be(nil))
  end
end
