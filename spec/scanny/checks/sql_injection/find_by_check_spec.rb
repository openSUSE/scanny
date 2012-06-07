require "spec_helper"

module Scanny::Checks
  describe FindByCheck do
    before do
      @runner       = Scanny::Runner.new(FindByCheck.new)
      @issue_low    = issue(:low, "SQL injection", 89)
      @issue_medium = issue(:medium, "SQL injection", 89)
      @issue_high   = issue(:high, "SQL injection", 89)
    end

    it "reports \"find_by_\" calls with \"params[:description]\" correctly" do
      @runner.should check("find_by_description(params[:description])").with_issue(@issue_low)
      @runner.should check("find_by_description(no_params[:description])").without_issues
    end

    it "reports \"find\" calls with :conditions key and static value correctly" do
      @runner.should check("find(:first, :conditions => { :id => 10 })").with_issue(@issue_low)
    end

    it "reports \"find\" calls with :conditions key and dynamic value correctly" do
      @runner.should check('find(:first, :conditions => { :id => "#{method}" })').with_issue(@issue_medium)
    end

    it "reports \"find\" calls with :conditions key and params method as value correctly" do
      @runner.should check("find(:first, :conditions => params[:id])").with_issue(@issue_high)
      @runner.should check("find(:first, :conditions => no_params[:id])").without_issues
    end

    it "reports \"find\" calls with :limit key and params method as value correctly" do
      @runner.should check("find(:first, :limit => params[:id])").with_issue(@issue_high)
      @runner.should check("find(:first, :limit => no_params[:id])").without_issues
    end

    it "reports \"find\" calls with :conditions key and session method as value correctly" do
      @runner.should check("find(:first, :conditions => session[:password])").with_issue(@issue_high)
      @runner.should check("find(:first, :conditions => no_session[:password])").without_issues
    end

    it "reports \"find\" calls with :limit key and session method as value correctly" do
      @runner.should check("find(:first, :conditions => session[:password])").with_issue(@issue_high)
      @runner.should check("find(:first, :conditions => no_session[:password])").without_issues
    end
  end
end
