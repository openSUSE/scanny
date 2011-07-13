module Scanny
  class Issue
    attr_reader :filename, :line_number, :impact, :message

    def initialize(filename, line_number, impact, message)
      @filename = filename
      @line_number = line_number
      @impact = impact
      @message = message
    end

    def to_s
      "[#{@impact}] #{@filename}:#{@line_number} - #{@message}"
    end
  end
end
