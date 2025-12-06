function out = baconian(text, direction)
%BACONIAN Cipher encoder/decoder
% Bacon's cipher uses a biliteral substitution alphabet based on two groups
% of letters. Each plaintext letter is represented by a 5-bit pattern.
% This implementation encodes each bit using letters from two halves of the
% alphabet:
%   0-bit -> random letter in A..M
%   1-bit -> random letter in N..Z
%
% The ciphertext is therefore a sequence of uppercase letters. Encrypting
% the same message twice will generally produce different ciphertext due to
% the random choice of letters for each bit.
%
% Syntax:
%   out = baconian(text, direction)
%
% Input:
%   text      - Character array or string scalar to encode or decode.
%              Only letters A-Z are used; all other characters are removed.
%   direction -  1 to encrypt
%               -1 to decrypt
%
% Output:
%   out - A structure with fields:
%       out.plain
%       out.encrypted
%
% Examples:
%   out = baconian('Hide the gold into the tree stump', 1)
%   out = baconian(out.encrypted, -1)
%
% Created by Giuseppe Cardillo
% giuseppe.cardillo.75@gmail.com

% ---- Input normalization and validation ----
if isstring(text)
    text = char(text);
end

p = inputParser;
p.FunctionName = mfilename;
addRequired(p, 'text', @(x) ischar(x));
addRequired(p, 'direction', @(x) validateattributes(x, {'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p, text, direction);

% ---- Preprocess text: keep only A-Z ----
% ASCII codes for uppercase letters range between 65 and 90
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];

% Scale each number between 0 and 25
ctext = ctext - 65;

% Split the alphabet in two halves
array0 = 0:12;   % A..M
array1 = 13:25;  % N..Z

switch direction
    case 1 % encrypt
        out.plain = text;

        L = numel(ctext);
        if L == 0
            out.encrypted = '';
            return;
        end

        % Convert into 5-bit binary (one row per letter)
        bintext = dec2bin(ctext, 5);

        % Preallocate ciphertext numeric codes (0..25)
        zAll = zeros(L, 5);

        for I = 1:L
            bits = bintext(I, :);

            idx0 = strfind(bits, '0');
            if ~isempty(idx0)
                % Random letters from the first array (without replacement)
                zAll(I, idx0) = array0(randperm(numel(array0), numel(idx0)));
            end

            idx1 = strfind(bits, '1');
            if ~isempty(idx1)
                % Random letters from the second array (without replacement)
                zAll(I, idx1) = array1(randperm(numel(array1), numel(idx1)));
            end
        end

        % Convert into ASCII letters
        out.encrypted = reshape(char(zAll + 65).', 1, []);

    case -1 % decrypt
        out.encrypted = text;

        L = numel(ctext);
        if L == 0
            out.plain = '';
            return;
        end

        assert(mod(L, 5) == 0, ...
            'The encrypted text length (letters only) must be a multiple of 5.');

        % Reshape into N-by-5 matrix of 0..25 codes
        x = reshape(ctext, 5, []).';

        % Rebuild bits: values > 12 correspond to 1-bits (N..Z)
        z = x > 12;

        % Convert each 5-bit row to a letter
        binStr = char(z + '0');      % N-by-5 char array
        decVal = bin2dec(binStr);    % 0..25
        out.plain = reshape(char(decVal + 65).', 1, []);
end
end
