require "spec_helper"

module Scanny::Checks::Sql
  describe FindMethodWithParamsCheck do
    before do
      @runner = Scanny::Runner.new(FindMethodWithParamsCheck.new)
      @message =  "Use of external parameters in queries to the database " +
                  "can lead to SQL injection issue"
      @issue_high = issue(:high, @message, 89)
    end

    it "reports \"find\" calls with :conditions key and params method as value correctly" do
      @runner.should  check("find(:first, :conditions => params[:id])").
                      with_issue(@issue_high)
      @runner.should_not  check("find(:first, :conditions => no_params[:id])").
                          with_issue(@issue_high)
    end

    it "reports \"find\" calls with :limit key and params method as value correctly" do
      @runner.should  check("find(:first, :limit => params[:id])").
                      with_issue(@issue_high)
      @runner.should_not  check("find(:first, :limit => no_params[:id])").
                          with_issue(@issue_high)
    end

    it "reports \"find\" calls with :conditions key and session method as value correctly" do
      @runner.should  check("find(:first, :conditions => session[:password])").
                      with_issue(@issue_high)
      @runner.should_not  check("find(:first, :conditions => no_session[:password])").
                          with_issue(@issue_high)
    end

    it "reports \"find\" calls with :limit key and session method as value correctly" do
      @runner.should  check("find(:first, :limit => session[:password])").
                      with_issue(@issue_high)
      @runner.should_not  check("find(:first, :limit => no_session[:password])").
                          with_issue(@issue_high)
    end

    it "does not report \"find\" calls when no first argument is given" do
      @runner.should  check("find(:limit => session[:password])").
                      without_issues
    end

    it "does not report \"find\" when hash keys are incorrect" do
      @runner.should  check("find(:first, :key => :limit, params[:hello] => :value)").
                      without_issues
    end

    it "reports \"execute\" calls on class with params correctly" do
      @runner.should check('User.execute params[:password]').with_issue(@issue_high)
    end

    it "reports \"find_by_sql\" calls on class with params correctly" do
      @runner.should  check('User.find_by_sql params[:password]').
                      with_issue(@issue_high)
    end

    it "reports \"paginate\" calls on class with params correctly" do
      @runner.should check('User.paginate params[:password]').with_issue(@issue_high)
    end

    it "reports \"execute\" calls on class with string interpolation correctly" do
      @runner.should  check('User.execute "#{params[:password]}"').
                      with_issue(@issue_high)
    end

    it "reports \"find_by_sql\" calls on class with string interpolation correctly" do
      @runner.should  check('User.find_by_sql "#{params[:password]}"').
                      with_issue(@issue_high)
    end

    it "reports \"paginate\" calls on class with string interpolation correctly" do
      @runner.should  check('User.paginate "#{params[:password]}"').
                      with_issue(@issue_high)
    end

    it "reports \"execute\" calls on object with string interpolation correctly" do
      @runner.should  check('@object.execute "#{params[:password]}"').
                      with_issue(@issue_high)
    end

    it "reports \"find_by_sql\" calls on object with string interpolation correctly" do
      @runner.should  check('@object.find_by_sql "#{params[:password]}"').
                      with_issue(@issue_high)
    end

    it "reports \"paginate\" calls on object with string interpolation correctly" do
      @runner.should  check('@object.paginate "#{params[:password]}"').
                      with_issue(@issue_high)
    end
  end
end
