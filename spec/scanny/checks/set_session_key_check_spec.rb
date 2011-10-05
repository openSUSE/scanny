require "spec_helper"

module Scanny::Checks
  describe SetSessionKeyCheck do
    before :each do
      @runner = Scanny::Runner.new(SetSessionKeyCheck.new)
      @issue = issue(:info, "Setting :session_key.", nil)
    end

    it "reports setting :session_key correctly" do
      @runner.should check('{ :session_key => "secret" }').with_issue(@issue)
      @runner.should check(
        '{ :foo => 42, :session_key => "secret", :bar => 43 }'
      ).with_issue(@issue)
      @runner.should check('{}').without_issues(@issue)
      @runner.should check(
        '{ :foo => 42, :bar => 43, :baz => 43 }'
      ).without_issues(@issue)
    end
  end
end
