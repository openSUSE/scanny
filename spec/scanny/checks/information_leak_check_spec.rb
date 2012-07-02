require "spec_helper"

module Scanny::Checks
  describe InformationLeakCheck do
    before do
      @runner = Scanny::Runner.new(InformationLeakCheck.new)
      @message = "There is a possibility of data leakage"
      @issue = issue(:medium, @message, 200)
    end

    it "reports \"filter_parameter_logging\" correctly" do
      @runner.should check("filter_parameter_logging").with_issue(@issue)
    end

    it "reports \"filter_parameter_logging :password\" correctly" do
      @runner.should  check("filter_parameter_logging :password").
                      with_issue(@issue)
    end

    it "reports \"User.find(params[:id])\" correctly" do
      @runner.should check("User.find(params[:id])").with_issue(@issue)
    end

    it "reports \"User.find_by_id(params[:id])\" correctly" do
      @runner.should check("User.find_by_id(params[:id])").with_issue(@issue)
    end

    it "reports \"User.find_by_name(params[:name])\" correctly" do
      @runner.should check("User.find(params[:name])").with_issue(@issue)
    end
  end
end
