require "spec_helper"

module Scanny::Checks
  describe SkipBeforeFiltersCheck do
    before :each do
      @runner = Scanny::Runner.new(SkipBeforeFiltersCheck.new)
      @login_required_issue = issue(:info,
        "The \"skip_before_filter\" method with :login_required filter is used.",
        [285, 288, 425])
      @admin_required_issue = issue(:info,
        "The \"skip_before_filter\" method with :admin_required filter is used.",
        [285, 288, 425])
      @verify_authenticity_token_issue = issue(:info,
        "The \"skip_before_filter\" method with :verify_authenticity_token filter is used.",
        [285, 288, 425])
      @authenticate_issue = issue(:info,
        "The \"skip_before_filter\" method with :authenticate filter is used.",
        [285, 288, 425])
    end

    it "reports \"skip_before_filter\" with :login_required filter correctly" do
      @runner.should check(
        'skip_before_filter :login_required'
      ).with_issue(@login_required_issue)
      @runner.should check(
        'self.skip_before_filter :login_required'
      ).with_issue(@login_required_issue)
      @runner.should check('foo.skip_before_filter :login_required').without_issues
      @runner.should check('skip_after_filter :login_required').without_issues
      @runner.should check(
        'skip_before_filter :some_filter, :login_required, :another_filter'
      ).with_issue(@login_required_issue)
      @runner.should check('skip_before_filter :some_filter').without_issues
    end

    it "reports \"skip_before_filter\" with :admin_required filter correctly" do
      @runner.should check(
        'skip_before_filter :admin_required'
      ).with_issue(@admin_required_issue)
      @runner.should check(
        'self.skip_before_filter :admin_required'
      ).with_issue(@admin_required_issue)
      @runner.should check('foo.skip_before_filter :admin_required').without_issues
      @runner.should check('skip_after_filter :admin_required').without_issues
      @runner.should check(
        'skip_before_filter :some_filter, :admin_required, :another_filter'
      ).with_issue(@admin_required_issue)
      @runner.should check('skip_before_filter :some_filter').without_issues
    end

    it "reports \"skip_before_filter\" with :verify_authenticity_token filter correctly" do
      @runner.should check(
        'skip_before_filter :verify_authenticity_token'
      ).with_issue(@verify_authenticity_token_issue)
      @runner.should check(
        'self.skip_before_filter :verify_authenticity_token'
      ).with_issue(@verify_authenticity_token_issue)
      @runner.should check('foo.skip_before_filter :verify_authenticity_token').without_issues
      @runner.should check('skip_after_filter :verify_authenticity_token').without_issues
      @runner.should check(
        'skip_before_filter :some_filter, :verify_authenticity_token, :another_filter'
      ).with_issue(@verify_authenticity_token_issue)
      @runner.should check('skip_before_filter :some_filter').without_issues
    end

    it "reports \"skip_before_filter\" with :authenticate filter correctly" do
      @runner.should check(
        'skip_before_filter :authenticate'
      ).with_issue(@authenticate_issue)
      @runner.should check(
        'self.skip_before_filter :authenticate'
      ).with_issue(@authenticate_issue)
      @runner.should check('foo.skip_before_filter :authenticate').without_issues
      @runner.should check('skip_after_filter :authenticate').without_issues
      @runner.should check(
        'skip_before_filter :some_filter, :authenticate, :another_filter'
      ).with_issue(@authenticate_issue)
      @runner.should check('skip_before_filter :some_filter').without_issues
    end
  end
end
