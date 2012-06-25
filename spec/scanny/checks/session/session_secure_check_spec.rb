require "spec_helper"

module Scanny::Checks::Session
  describe SessionSecureCheck do
    before do
      @runner = Scanny::Runner.new(SessionSecureCheck.new)
      @message = "Bad session security setting can cause problems"
      @issue = issue(:info, @message, 614)
    end

    it "reports \":session_secure\" correctly" do
      @runner.should check(":session_secure").with_issue(@issue)
    end

    it "reports \":secure\" correctly" do
      @runner.should check(":secure").with_issue(@issue)
    end

    it "reports \"ActionController::Base.session_options[:session_secure] = false\" correctly" do
      @runner.should  check("ActionController::Base.session_options[:session_secure] = false").
                      with_issue(@issue)
    end

    it "reports \"ActionController::Base.session_options[:secure] = false\" correctly" do
      @runner.should  check("ActionController::Base.session_options[:secure] = false").
                      with_issue(@issue)
    end
  end
end

