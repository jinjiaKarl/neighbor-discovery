% Provided means and confidence intervals
y = [0.006822266340255737, 0.002534996271133423; 0.006600338935852051, 0.002465487003326416; 0.0064318904876708985, 0.002290135622024536; 0.006280163288116455, 0.002235590219497681];
err = [0.0003431264174062662, 4.573172257650856e-05; 0.0003208890074537406, 3.6488564786921726e-05; 0.0003136036067404623, 2.9059012252310827e-05; 0.0003021933053031728, 3.134665709538781e-05];

% Categories
categories = {'Sign', 'Verify'};
sessions = {"0", "15", "25", "50" };
% Custom colors for bars
barColors = [0.4 0.4 0.4; 0.8 0.8 0.8];
% Plot
fig = figure(1); clf; 
hb = bar(y); % get the bar handles
hold on;
% Set custom colors for bars
for k = 1:size(y, 2)
    hb(k).FaceColor = barColors(k, :);
end
% Aligning error bars to individual bar within groups
groupwidth = min(0.8, 2/(2+1.5));
for k = 1:size(y, 2)
    xpos = (1:size(y, 1)) - groupwidth/2 + (2*k-1) * groupwidth / (2*size(y, 2));
    errorbar(xpos, y(:, k), err(:, k), 'LineStyle', 'none', 'Color', 'k', 'LineWidth', 1);
end
grid on;
% Set Axis properties
set(gca, 'xticklabel', sessions);
ylim([0, max(y(:)) + 0.002]);  % Adjust ylim based on your data
ylabel('Time [s]');
xlabel('Distance [m]');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
print(fig, '-bestfit', 'locationbased_signverify','-dpdf');
