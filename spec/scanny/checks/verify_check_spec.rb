require "spec_helper"

module Scanny::Checks
  describe VerifyMethodCheck do
    before do
      @runner = Scanny::Runner.new(VerifyMethodCheck.new)
      @message =  "Incorrect to use the verify method can lead to " +
                  "accept additional parameters from request"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"verify :method => :post, :only => [:create]\" correctly" do
      @runner.should  check("verify :method => :post, :only => [:create]").
                      with_issue(@issue)
    end

    it "reports \"verify :params => 'user', :only => :update_password\" correctly" do
      @runner.should  check("verify :params => 'user', :only => :update_password").
                      without_issues
    end

    it "does not report \"verify :argument, :method => :post\"" do
      @runner.should  check("verify :argument, :method => :post").
                      without_issues
    end
  end
end
