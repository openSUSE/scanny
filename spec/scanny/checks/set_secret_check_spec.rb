require "spec_helper"

module Scanny::Checks
  describe SetSecretCheck do
    before :each do
      @runner = Scanny::Runner.new(SetSecretCheck.new)
      @issue = issue(:info,
        "Setting :secret can indicate using hard-coded cryptographic key.", 321)
    end

    it "reports setting :secret correctly" do
      @runner.should check('{ :secret => "secret" }').with_issue(@issue)
      @runner.should check(
        '{ :foo => 42, :secret => "secret", :bar => 43 }'
      ).with_issue(@issue)
      @runner.should check('{}').without_issues(@issue)
      @runner.should check(
        '{ :foo => 42, :bar => 43, :baz => 43 }'
      ).without_issues(@issue)
    end
  end
end
