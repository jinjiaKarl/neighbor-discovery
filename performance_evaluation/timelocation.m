% Provided means and confidence intervals
%total time
%y = [0.47617726348899997, 0.9768291537780001; 0.894993547199, 1.576954938177; 1.228557272438, 2.083077701316];
% err = [0.010702849964520728, 0.023356187917318222; 0.02535022892046689, 0.04158563627653643; 0.038424744389013, 0.05820132530917114];

%hmac
 
%y = [0.000645174959, 0.000575619448; 0.0006641137639999999, 0.0005888085190000001; 0.000492636428, 0.000566910514];
%err = [4.430312122813697e-05, 4.119097449444999e-05; 6.659064133870705e-05, 3.393421695886889e-05; 4.030791260036383e-05, 3.891464676904837e-05];

%AES-GCM

y = [0.0007973482608795166, 0.0006659030914306641; 0.0008128354549407959, 0.000783167839050293; 0.0006284985542297363, 0.0007302477359771728];
err = [5.3599933287003926e-05, 3.471765395075152e-05; 5.487333512303911e-05, 4.518213685221131e-05; 3.280417615270333e-05, 4.574099945903751e-05];


% Categories
categories = {'15 m', '30 m'};
sessions = {'25%', '50%', '75%'};
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
ylim([0, max(y(:)) + 0.0004]);  % Adjust ylim based on your data
%ylabel('Total Time [s]');
%ylabel('HMAC Comparison Time [s]');
ylabel('AES-GCM Encryption Time [s]');
xlabel('Noise level');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
% print(fig, '-bestfit', 'timelocation_totaltime','-dpdf');
%print(fig, '-bestfit', 'timelocation_HMAC_Comparison','-dpdf');
print(fig, '-bestfit', 'timelocation_AES_GCM','-dpdf');

