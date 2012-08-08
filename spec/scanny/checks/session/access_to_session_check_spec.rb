require "spec_helper"

module Scanny::Checks::Session
  describe AccessToSessionCheck do
    before do
      @runner = Scanny::Runner.new(AccessToSessionCheck.new)
      @message =  "Referring to a session in the wrong way" +
                  "can lead to errors that reduce security level"
      @issue = issue(:info, @message)
    end

    it "reports \"session[:password]\" correctly" do
      @runner.should check("session[:password]").with_issue(@issue)
    end

    it "reports \"cookie[:password]\" correctly" do
      @runner.should check("cookie[:password]").with_issue(@issue)
    end

    it "reports \"session[:password] = params[:input]\" correctly" do
      @runner.should check("session[:password] = nil").with_issue(@issue)
    end

    it "reports \"cookie[:password] = params[:input]\" correctly" do
      @runner.should check("cookie[:password] = nil").with_issue(@issue)
    end
  end
end

