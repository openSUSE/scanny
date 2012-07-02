require "spec_helper"

module Scanny::Checks
  describe UserFindCheck do
    before do
      @runner = Scanny::Runner.new(UserFindCheck.new)
      @message =  "Create a user object using the " +
                  "parameters can cause security problems"
      @issue = issue(:medium, @message, [89, 592])
    end

    it "reports \"User.find(params[:input])\" correctly" do
      @runner.should  check("User.find(params[:input])").
                      with_issue(@issue)
    end

    it "reports \"User.find(:first)\" correctly" do
      @runner.should  check("User.find(:first)").
                      without_issues
    end
  end
end
