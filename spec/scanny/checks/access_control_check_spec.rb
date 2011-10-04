require "spec_helper"

module Scanny::Checks
  describe AccessControlCheck do
    before :each do
      @runner = Scanny::Runner.new(AccessControlCheck.new)
      @issue = issue(:medium,
        "Using \"params[:id]\" requires proper authorization check.", 285)
    end

    it "reports \"new\" calls with \"params[:id]\" in the attributes hash correctly" do
      @runner.should check('User.new(:id => params[:id])').with_issue(@issue)
      @runner.should check(
        'User.new(:foo => 42, :id => params[:id], :bar => 43)'
      ).with_issue(@issue)
      @runner.should check('User.new(:id => not_params[:id])').without_issues
      @runner.should check('User.new(:id => params[:not_id])').without_issues
    end

    it "reports \"create\" calls with \"params[:id]\" in the attributes hash correctly" do
      @runner.should check('User.create(:id => params[:id])').with_issue(@issue)
      @runner.should check(
        'User.create(:foo => 42, :id => params[:id], :bar => 43)'
      ).with_issue(@issue)
      @runner.should check('User.create(:id => not_params[:id])').without_issues
      @runner.should check('User.create(:id => params[:not_id])').without_issues
    end

    it "reports \"delete\" calls with \"params[:id]\" in the arguments" do
      @runner.should check('User.delete(params[:id])').with_issue(@issue)
      @runner.should check('User.delete(42, params[:id], 43)').with_issue(@issue)
      @runner.should check('User.new(not_params[:id])').without_issues
      @runner.should check('User.new(params[:not_id])').without_issues
    end

    it "reports \"destroy\" calls with \"params[:id]\" in the arguments" do
      @runner.should check('User.destroy(params[:id])').with_issue(@issue)
      @runner.should check('User.destroy(42, params[:id], 43)').with_issue(@issue)
      @runner.should check('User.new(not_params[:id])').without_issues
      @runner.should check('User.new(params[:not_id])').without_issues
    end
  end
end
