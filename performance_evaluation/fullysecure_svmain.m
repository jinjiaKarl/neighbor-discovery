% Provided means and confidence intervals

y_25 = [0.005415184942180504, 0.001354575634958271; 0.006439664840698242, 0.001281404972076416];
err_25 = [0.00031581522126066343, 1.458984097397086e-05; 0.0003621617631469964, 6.218096347874909e-06];

y_50 = [0.006060711622238159, 0.0013243000507354736; 0.006109509706497192, 0.0013110690116882324];
err_50 = [0.00034426939343693236, 8.390080605920294e-06; 0.0003417963473881111, 6.836643286560937e-06];

y_75 =[0.006096341545388117, 0.0013464869802430975; 0.006090725183486938, 0.0014090447425842286];
err_75 = [0.00033360987985184493, 7.569044375645356e-06; 0.00033705670718518066, 1.4125988098524008e-05];
% Categories
categories = {'Sign', 'Verify'};
sessions = { "15", "30" };
% Custom colors for bars
barColors = [0.4 0.4 0.4; 0.8 0.8 0.8];

% Plot Total Time
figure;
fig = figure; clf; 
subplot(1, 3, 1);
hb_total_time = bar(y_25);
title('25% Noise');
hold on;
for k = 1:size(y_25, 2)
    hb_total_time(k).FaceColor = barColors(k, :);
end
groupwidth = min(0.8, 2/(2+1.5));
for k = 1:size(y_25, 2)
    xpos = (1:size(y_25, 1)) - groupwidth/2 + (2*k-1) * groupwidth / (2*size(y_25, 2));
    errorbar(xpos, y_25(:, k), err_25(:, k), 'LineStyle', 'none', 'Color', 'k', 'LineWidth', 1);
end
grid on;
set(gca, 'xticklabel', sessions);
ylim([0, max(y_25(:)) + 0.004]);
ylabel('Time [s]');
xlabel('Distance [m]');
%legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);

% Plot HMAC
subplot(1, 3, 2);
hb_hmac = bar(y_50);
title('50% Noise');
hold on;
for k = 1:size(y_50, 2)
    hb_hmac(k).FaceColor = barColors(k, :);
end
groupwidth = min(0.8, 2/(2+1.5));
for k = 1:size(y_50, 2)
    xpos = (1:size(y_50, 1)) - groupwidth/2 + (2*k-1) * groupwidth / (2*size(y_50, 2));
    errorbar(xpos, y_50(:, k), err_50(:, k), 'LineStyle', 'none', 'Color', 'k', 'LineWidth', 1);
end
grid on;
set(gca, 'xticklabel', sessions);
ylim([0, max(y_50(:)) + 0.004]);
ylabel('Time [s]');
xlabel('Distance [m]');
%legend(categories, 'Location', 'best');
set(gca, 'Fontsize', 25);

% Plot AES-GCM
subplot(1, 3, 3);
hb_aes_gcm = bar(y_75);
title('75% Noise');
hold on;
for k = 1:size(y_75, 2)
    hb_aes_gcm(k).FaceColor = barColors(k, :);
end
groupwidth = min(0.8, 2/(2+1.5));
for k = 1:size(y_75, 2)
    xpos = (1:size(y_75, 1)) - groupwidth/2 + (2*k-1) * groupwidth / (2*size(y_75, 2));
    errorbar(xpos, y_75(:, k), err_75(:, k), 'LineStyle', 'none', 'Color', 'k', 'LineWidth', 1);
end
grid on;
set(gca, 'xticklabel', sessions);
ylim([0, max(y_75(:)) + 0.004]);
ylabel('Time [s]');
xlabel('Distance [m]');
legend(categories, 'Location', 'northeast', FontSize=15);
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
% Save the figure as a PDF
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]);
print(fig, '-bestfit', 'fullysecure_signverify', '-dpdf');
