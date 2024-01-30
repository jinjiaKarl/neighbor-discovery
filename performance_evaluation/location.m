% Total time in time based protocol code
clear all; clc; close all
format longEng

% Total Time, Signature Verification Time, HMAC Comparison Time, Signing Time, AES-GCM Encryption Time
% load the files
location0 = load("processed_location_based_protocol_distance_0.txt");
location15 = load("processed_location_based_protocol_distance_15.txt");
location25 = load("processed_location_based_protocol_distance_25.txt");
location50 = load("processed_location_based_protocol_distance_50.txt");

% compute the mean for total time
location0_mean = mean(location0(:, 5));
location15_mean = mean(location15(:, 5));
location25_mean = mean(location25(:, 5));
location50_mean = mean(location50(:, 5));

% label = ["MD5" "Blake"];
cats = ["0", "15", "25", "50"];
data = [location0_mean location15_mean location25_mean location50_mean];

% CI95 for time
[yMean_location0, yCI95_location0] = CI95(location0(:, 5));
[yMean_location15, yCI95_location15] = CI95(location15(:, 5));
[yMean_location25, yCI95_location25] = CI95(location25(:, 5));
[yMean_location50, yCI95_location50] = CI95(location50(:, 5));

fig = figure;

b = bar(cats, data);
b(1).FaceColor = [0.75 0.75 0.75];
hold on
errorbar(1, data(1), yCI95_location0(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(2, data(2), yCI95_location15(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(3, data(3), yCI95_location25(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(4, data(4), yCI95_location50(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)


hold off
grid on;
xlabel('Distance [m]');
ylabel('AES-GCM Encryption Time [s]');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
print(fig, '-bestfit', 'location_AES_GCM_Encryption_time','-dpdf');


% CI95 function
function [yMean, yCI95] = CI95(data)
    N = size(data, 1);
    yMean = mean(data);
    ySEM = std(data)/sqrt(N);
    CI95 = tinv([0.025 0.975], N-1);
    yCI95 = bsxfun(@times, ySEM, CI95(:));
end
