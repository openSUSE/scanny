module Scanny
  class Issue
    attr_reader :file, :line, :impact, :message

    def initialize(file, line, impact, message)
      @file, @line, @impact, @message = file, line, impact, message
    end

    def to_s
      "[#{@impact}] #{@file}:#{@line} - #{@message}"
    end
  end
end
