% Provided means and confidence intervals

y16 = [0.014582546241403876, 0.0006718958299198641;
    0.029840867354138063, 0.0009304577761357374;
    0.04663140296936035, 0.0010159826278686524];
err16 = [0.0001351206819696579, 1.5804531398140555e-05;
    0.0002877790723398541, 2.511351488810826e-05;
    0.00016193672708545343, 1.4674636987649082e-05];
y24 = [0.015648428107455016, 0.0008414389751211475; 0.030949814553054147, 0.0009880720325304646; 0.05053998041152954, 0.0011748886108398438];
err24 = [0.0001697898169885118, 2.930420150366141e-05; 0.000332897415907029, 3.571737960689547e-05; 0.0002792636814127526, 4.611083038536753e-05];

y=[0.014332442045211792, 0.0006884934902191163; 0.02821836256980896, 0.0009072356224060059; 0.04750429761820826, 0.0010904802216423883];
err=[0.0001278715643989987, 1.3361500707527713e-05; 0.00015766534266814484, 2.3004745378324572e-05; 0.0003324533064550991, 2.3125794979394142e-05];


% Categories
categories = {'Sign', 'Verify'};
sessions = {'1024', '2048', '3072'};
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
ylim([0, max(y(:)) + 0.02]);  % Adjust ylim based on your data
ylabel('Time [s]');
xlabel('Key Size [bits]');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);

% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
print(fig, '-bestfit', 'bp6_receiver','-dpdf');
