require "spec_helper"

module Scanny::Checks
  describe CSRFCheck do
    before :each do
      @runner = Scanny::Runner.new(CSRFCheck.new)
      @issue = issue(:info, "The \"protect_from_forgery\" method is used.", 352)
    end

    it "reports \"protect_from_forgery\" correctly" do
      @runner.should check('protect_from_forgery').with_issue(@issue)
      @runner.should check('self.protect_from_forgery').with_issue(@issue)
      @runner.should check('foo.protect_from_forgery').without_issues
    end
  end
end
