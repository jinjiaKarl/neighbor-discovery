% Provided means and confidence intervals


y16= [0.018123218283639622, 0.000375463123885192; 0.035068254895729595, 0.0005498182655561089; 0.05121565294265747, 0.0006817164421081543];
err16 = [0.00019091520062789046, 1.1100956326873744e-05; 0.00036138605269717686, 1.4430545170802681e-05; 0.00020389705015509866, 1.2048862076354423e-05];
y24=[0.020407842606613318, 0.000400292504694044; 0.03649234389034167, 0.0005720365870247684; 0.05438740921020508, 0.0007446937561035157];
err24 = [0.0002387500213516016, 1.0705173670855446e-05; 0.00042877530470019693, 1.1424137042947419e-05; 0.00028045868017542697, 1.2306485884666598e-05];

y=[0.018048154592514038, 0.00038605642318725587; 0.032503641843795776, 0.0005062334537506104; 0.05254147290269991, 0.0007325698589456493];
err=[0.0001644009999808625, 1.614374960700189e-05; 0.00023708223073276412, 1.1698758463230092e-05; 0.0003060629932860832, 2.1458020649830675e-05];

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
print(fig, '-bestfit', 'bp7_transmitter','-dpdf');


