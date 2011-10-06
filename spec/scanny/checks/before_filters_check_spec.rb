require "spec_helper"

module Scanny::Checks
  describe BeforeFiltersCheck do
    before :each do
      @runner = Scanny::Runner.new(BeforeFiltersCheck.new)
      @login_required_issue = issue(:info,
        "The \"before_filter\" method with :login_required filter is used.",
        nil)
      @admin_required_issue = issue(:info,
        "The \"before_filter\" method with :admin_required filter is used.",
        nil)
    end

    it "reports \"before_filter\" with :login_required filter correctly" do
      @runner.should check(
        'before_filter :login_required'
      ).with_issue(@login_required_issue)
      @runner.should check(
        'self.before_filter :login_required'
      ).with_issue(@login_required_issue)
      @runner.should check('foo.before_filter :login_required').without_issues
      @runner.should check('after_filter :login_required').without_issues
      @runner.should check(
        'before_filter :some_filter, :login_required, :another_filter'
      ).with_issue(@login_required_issue)
      @runner.should check('before_filter :some_filter').without_issues
    end

    it "reports \"before_filter\" with :admin_required filter correctly" do
      @runner.should check(
        'before_filter :admin_required'
      ).with_issue(@admin_required_issue)
      @runner.should check(
        'self.before_filter :admin_required'
      ).with_issue(@admin_required_issue)
      @runner.should check('foo.before_filter :admin_required').without_issues
      @runner.should check('after_filter :admin_required').without_issues
      @runner.should check(
        'before_filter :some_filter, :admin_required, :another_filter'
      ).with_issue(@admin_required_issue)
      @runner.should check('before_filter :some_filter').without_issues
    end
  end
end
