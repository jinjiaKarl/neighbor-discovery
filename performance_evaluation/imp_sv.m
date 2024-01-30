% Provided means and confidence intervals

y=[0.006564883596868629, 0.006520912941708507; 0.006051538947099697, 0.005561431011040054; 0.006058361768722534, 0.005891749143600464; 0.006547189566243692, 0.006542247367570125];
err= [0.00010159267676825474, 6.308378696437113e-05; 0.00013481461859947517, 0.00011469473760491306; 0.00010595953958644354, 7.58783029458119e-05; 0.00014246913303981988, 6.784432653382387e-05];
y25519 = [0.00286500883102417, 0.0022455451488494873; 0.0026629517078399657, 0.0021166069507598875; 0.003952840685844421, 0.0029152346849441527; 0.0029830316999065343, 0.002293733221974539];
err25519= [9.580028964922379e-05, 3.0766237401590583e-05; 8.664116379797567e-05, 3.11317687900526e-05; 0.0001683421276062035, 0.00011390469625630151; 0.00010322642628249198, 6.248683339195223e-05];
% Categories
categories = {'Sign', 'Verify'};
sessions = {"Blake"; "MD5"; "SHA256"; "SHA3-256" };
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
xlabel('Ed448 Algorithm');

% Add legend and customize as needed
legend(categories, 'Location', 'bestoutside');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
% Save the figure as a PDF with legend outside the plot
set(gcf, 'PaperUnits', 'inches', 'PaperPosition', [0 0 8 6]); % Adjust size if needed
print(fig, '-bestfit', 'imp_signverifyed448','-dpdf');
