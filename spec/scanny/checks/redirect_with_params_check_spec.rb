require "spec_helper"

module Scanny::Checks
  describe RedirectWithParamsCheck do
    before do
      @runner = Scanny::Runner.new(RedirectWithParamsCheck.new)
      @message =  "Use of external parameters in redirect_to method" +
                  "can lead to unauthorized redirects"
      @issue = issue(:medium, @message, [79, 113, 601, 698])
    end

    it "reports \"redirect_to(params[:to])\" correctly" do
      @runner.should check("redirect_to(params[:to])").with_issue(@issue)
      @runner.should check("redirect_to(@user)").without_issues
    end

    it "reports \"redirect_to\" with hash correctly" do
      @runner.should
        check("redirect_to :controller => :my, :action => params[:action]").with_issue(@issue)
      @runner.should
        check("redirect_to :controller => :my, :action => :new").without_issues
    end
  end
end
