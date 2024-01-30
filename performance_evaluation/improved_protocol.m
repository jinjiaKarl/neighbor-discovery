clear all; clc; close all
format longEng

% Total Time, Signature Verification Time, HMAC Comparison Time, Signing Time, AES-GCM Encryption Time
% load the files
md5 = load("improved_protocol_ed448_MD5.txt");
blake = load("improved_protocol_ed448_BLAKE2b.txt");
sha3 = load("improved_protocol_ed448_SHA3_256.txt");
hmac_sha256 = load("improved_protocol_ed448_SHA256.txt");

% compute the mean for total time
md5_mean = mean(md5(:, 3));
blake_mean = mean(blake(:, 3));
sha3_mean = mean(sha3(:, 3));
hmac_sha256_mean = mean(hmac_sha256(:, 3));

% label = ["MD5" "Blake"];
cats = categorical(["MD5"; "Blake"; "SHA3-256"; "SHA256"]);
data = [md5_mean blake_mean sha3_mean hmac_sha256_mean];

% CI95 for time
[yMean_md5, yCI95_md5] = CI95(md5(:, 3));
[yMean_blake, yCI95_blake] = CI95(blake(:, 3));
[yMean_sha3, yCI95_sha3] = CI95(sha3(:, 3));
[yMean_hmac_sha256, yCI95_hmac_sha256] = CI95(hmac_sha256(:, 3));

fig = figure;

b = bar(cats, data);
b(1).FaceColor = [0.75 0.75 0.75];
hold on
errorbar(1, data(2), yCI95_md5(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(2, data(1), yCI95_blake(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(3, data(4), yCI95_sha3(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)
errorbar(4, data(3), yCI95_hmac_sha256(2),'*k', 'LineWidth', 1.25, 'MarkerSize', 5)


hold off
grid on;
xlabel('Ed448 Algorithm');
ylabel('HMAC Comparison Time [s]');
set(gca, 'Fontsize', 25);
orient(fig, 'landscape');
print(fig, '-bestfit', 'HMAC_Comparison_Time_Ed448','-dpdf');

% CI95 function
function [yMean, yCI95] = CI95(data)
    N = size(data, 1);
    yMean = mean(data);
    ySEM = std(data)/sqrt(N);
    CI95 = tinv([0.025 0.975], N-1);
    yCI95 = bsxfun(@times, ySEM, CI95(:));
end
