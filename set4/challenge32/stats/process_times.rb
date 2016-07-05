OUTPUT_FILE_NAME = 'plot.png'
X_AXIS_LABEL = 'Time (ms)'

def process(file)
  times = []
  File.foreach(file) do |l|
    times << l.to_i
  end

  freq_distribution = Array.new((times.max / 10000) + 1, 0)

  times.each do |t|
    freq_distribution[t / 10000] += 1
  end

  freq_distribution
end

distributions = (0..2).map {|i| process("times_#{i}.txt") }

def distribution_to_plot(distribution)
  from = 0
  to = 300
  distribution[from...to].map.with_index do |count, i|
    "#{(i + from).to_f / 100}    #{count}" if count > 0
  end.join("\n")
end

gnuplot_commands = %Q{
set terminal png
set output '#{OUTPUT_FILE_NAME}'
set xlabel '#{X_AXIS_LABEL}'

#{distributions.map.with_index do |dist, i| 
"$data#{i} << EOD
#{distribution_to_plot(dist)}
EOD
"
end.join}

plot $data0 title "18 (incorrect)", $data1 title "19 (correct)", \
  $data2 title "20 (incorrect)"
}

def gnuplot(commands)
  IO.popen("gnuplot", "w") { |io| io.puts commands }
end

gnuplot(gnuplot_commands)
