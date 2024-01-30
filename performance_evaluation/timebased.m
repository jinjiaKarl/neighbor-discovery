% Total time in time based protocol code
clear all; clc; close all
format longEng

% Total Time, Signature Verification Time, HMAC Comparison Time, Signing Time, AES-GCM Encryption Time
% load the files
time0 = load("processed_receiver_time_0_protocol.txt");
time25 = load("processed_receiver_time_25_protocol.txt");
time50 = load("processed_receiver_time_50_protocol.txt");
time75 = load("processed_receiver_time_75_protocol.txt");
time100 = load("processed_receiver_time_100_protocol.txt");


% compute the mean for total time
time0_mean = mean(time0(:, 5));
time25_mean = mean(time25(:, 5));
time50_mean = mean(time50(:, 5));
time75_mean = mean(time75(:, 5));
time100_mean = mean(time100(:, 5));
% label = ["MD5" "Blake"];
cats = ["0%", "25%", "50%", "75%", "100%"];
data = [time0_mean time25_mean time50_mean time75_mean time100_mean];

% CI95 for time
[yMean_time0, yCI95_time0] = CI95(time0(:, 5));
[yMean_time25, yCI95_time25] = CI95(time25(:, 5));
[yMean_time50, yCI95_time50] = CI95(time50(:, 5));
[yMean_time75, yCI95_time75] = CI95(time75(:, 5));
[yMean_time100, yCI95_time100] = CI95(time100(:, 5));

fig = figure;

b = bar(cats, data);
b(1).FaceColor = [0.75 0.75 0.75];
hold on
errorbar(1, data(1), yCI95_time0(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(2, data(2), yCI95_time25(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(3, data(3), yCI95_time50(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(4, data(4), yCI95_time75(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(5, data(5), yCI95_time100(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)

hold off
grid on;
xlabel('Noise level');
ylabel('AES-GCM Encryption Time [s]');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
print(fig, '-bestfit', 'timebased_AES_GCM_Encryption_time','-dpdf');


% CI95 function
function [yMean, yCI95] = CI95(data)
    N = size(data, 1);
    yMean = mean(data);
    ySEM = std(data)/sqrt(N);
    CI95 = tinv([0.025 0.975], N-1);
    yCI95 = bsxfun(@times, ySEM, CI95(:));
end
