require "spec_helper"

module Scanny::Checks
  describe SetRailsEnvCheck do
    before :each do
      @runner = Scanny::Runner.new(SetRailsEnvCheck.new)
      @issue = issue(:info,
        "Setting ENV[\"RAILS_ENV\"] can indicate insecure configuration.", 209)
    end

    it "reports setting ENV[\"RAILS_ENV\"] correctly" do
      @runner.should check('ENV["RAILS_ENV"] = "test"').with_issue(@issue)
      @runner.should check('FOO["RAILS_ENV"] = "test"').without_issues
      @runner.should check('ENV["FOO"] = "test"').without_issues
    end
  end
end
