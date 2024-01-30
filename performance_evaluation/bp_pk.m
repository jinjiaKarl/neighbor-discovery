% Provided means and confidence intervals

y16 = [0.0005700699594386767, 0.013623239655399182; 0.0008278889231162496, 0.030063352726473622; 0.0009392278194427491, 0.04714986681938167];
err16 = [1.2851381834752708e-05, 0.00012838582912741086; 4.106422171991972e-05, 0.0002889632217825048; 1.1317858761214179e-05, 0.00014495680640748334];

y24 = [0.0006838680542621416, 0.0153907238412968; 0.0008460775041656739, 0.03083284517352496; 0.0010726675987243652, 0.048980937480926474];
err24 = [1.8002100744285715e-05, 0.0002684581858170488; 1.3042172002929906e-05, 0.0003783722674736023; 4.1373082064092804e-05, 0.00022967904545645112];

y = [0.0006216580867767333, 0.013667469263076732; 0.0008595192432403565, 0.02808034396171565; 0.0010400412183155046, 0.048846371329150394];
err = [1.6138651792215775e-05, 0.00011649939733719513; 2.51609628675309e-05, 0.00013315658490800262; 2.1973409797349688e-05, 0.0004199764133731653];

% Categories
categories = {'Encrypt', 'Decrypt'};
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
xlabel('AES-32');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);

% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
print(fig, '-bestfit', 'pk32','-dpdf');
