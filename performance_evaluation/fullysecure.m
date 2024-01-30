% Provided means and confidence intervals
%total time
% y = [0.4643623730961923, 0.892800181877; 1.363369901888, 1.475816080813; 1.2832021655967907, 2.0995406453570005];
% err = [0.010726900991798408, 0.019598923211712353; 0.0397532772447556, 0.039758636844247616; 0.2809848289627865, 0.05796132478029528];
%hmac
 %y = [0.0002093107244488978, 0.00020591307200000002; 0.00020945549899999998, 0.000208220967; 0.00021399012838515548, 0.00023411869199999998];
 %err = [2.301790065783092e-06, 1.98345245825602e-06; 2.013716501333035e-06, 2.343619313212173e-06; 1.8910709824104726e-06, 3.781265302244271e-06];
%AES-GCM
y = [0.0005616671097780278, 0.0006758770942687988; 0.0006344671249389649, 0.0006829409599304199; 0.0005388169016020229, 0.0007307648658752442];
err = [2.9290171717760046e-05, 3.890340987341698e-05; 2.9463592781056343e-05, 2.9216575361843346e-05; 2.4898590240741243e-05, 4.9957326574023144e-05];

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
%ylabel('HMAC Comparison Time [s]');
ylabel('AES-GCM Encryption Time [s]');
xlabel('Noise level');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
% print(fig, '-bestfit', 'totaltime_fullysecure','-dpdf');
%print(fig, '-bestfit', 'HMAC_Comparison_fullysecure','-dpdf');
print(fig, '-bestfit', 'AES_GCM_fullysecure','-dpdf');

