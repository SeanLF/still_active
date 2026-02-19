# frozen_string_literal: true

RSpec.describe(StillActive::CLI) do
  subject(:cli) { described_class.new }

  let(:recent_date) { Time.now }
  let(:old_date) { Time.new(Time.now.year - 2, 1, 1) }
  let(:ancient_date) { Time.new(Time.now.year - 5, 1, 1) }

  let(:workflow_result) { {} }

  before do
    allow(StillActive::Workflow).to(receive(:call).and_return(workflow_result))
    allow($stdout).to(receive(:puts))
    StillActive.reset
  end

  def gem_data(last_commit_date:)
    {
      last_commit_date: last_commit_date,
      latest_version_release_date: nil,
      latest_pre_release_version_release_date: nil,
      version_used: "1.0.0",
      latest_version: "1.0.0",
      latest_pre_release_version: nil,
    }
  end

  describe("--fail-if-critical") do
    context("when a gem has critical activity warning") do
      let(:workflow_result) { { "stale_gem" => gem_data(last_commit_date: ancient_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=stale_gem", "--json", "--fail-if-critical"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when no gems have critical activity warning") do
      let(:workflow_result) { { "fresh_gem" => gem_data(last_commit_date: recent_date) } }

      it("exits 0") do
        expect { cli.run(["--gems=fresh_gem", "--json", "--fail-if-critical"]) }
          .not_to(raise_error)
      end
    end
  end

  describe("--fail-if-warning") do
    context("when a gem has warning activity") do
      let(:workflow_result) { { "aging_gem" => gem_data(last_commit_date: old_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=aging_gem", "--json", "--fail-if-warning"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when a gem has critical activity warning") do
      let(:workflow_result) { { "stale_gem" => gem_data(last_commit_date: ancient_date) } }

      it("exits 1") do
        expect { cli.run(["--gems=stale_gem", "--json", "--fail-if-warning"]) }
          .to(raise_error(SystemExit) { |e| expect(e.status).to(eq(1)) })
      end
    end

    context("when all gems are fresh") do
      let(:workflow_result) { { "fresh_gem" => gem_data(last_commit_date: recent_date) } }

      it("exits 0") do
        expect { cli.run(["--gems=fresh_gem", "--json", "--fail-if-warning"]) }
          .not_to(raise_error)
      end
    end
  end
end
