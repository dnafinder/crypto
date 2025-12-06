function out = swagman(text, direction, varargin)
%SWAGMAN Cipher encoder/decoder
% The Swagman is a transposition cipher that uses a Latin Square.
% In combinatorics and experimental design, a Latin square is an n-by-n
% matrix filled with n different symbols, each occurring exactly once in
% each row and exactly once in each column. Example of a 3x3 Latin square:
%   A B C
%   C A B
%   B C A
%
% Syntax:
%   out = swagman(text, direction)
%   out = swagman(text, direction, LS)
%
% Input:
%   text      - Character array or string scalar to encode or decode.
%               Only letters A-Z are used by the algorithm; all other
%               characters are removed.
%   direction - This parameter can assume only two values:
%                 1  to encrypt
%                -1  to decrypt
%   LS        - Latin square (numeric n-by-n, containing integers 1:n).
%               If empty and direction is 1, the software will generate it.
%               It is mandatory to decrypt.
%
% Output:
%   out - A structure with fields:
%       out.plain      - The plain text (as provided for encryption, or
%                        recovered for decryption).
%       out.LS         - The used Latin Square.
%       out.encrypted  - The coded text.
%
% Examples:
%   LS = [1 4 5 3 2; 3 1 2 5 4; 4 2 3 1 5; 5 3 4 2 1; 2 5 1 4 3];
%   out = swagman('Hide the gold into the tree stump', 1, LS)
%
%   out =
%     struct with fields:
%           plain: 'Hide the gold into the tree stump'
%              LS: [5×5 double]
%       encrypted: 'HUENTGTRIMPOOEDTEELSTDHHIET'
%
%   out = swagman('HUENTGTRIMPOOEDTEELSTDHHIET', -1, LS)
%
%   out =
%     struct with fields:
%       encrypted: 'HUENTGTRIMPOOEDTEELSTDHHIET'
%              LS: [5×5 double]
%           plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
% Created by Giuseppe Cardillo
% giuseppe.cardillo.75@gmail.com

% ---- Input handling ----
if isstring(text)
    text = char(text);
end

p = inputParser;
p.FunctionName = mfilename;

addRequired(p, 'text', @(x) ischar(x) && (isrow(x) || isempty(x)));
addRequired(p, 'direction', @(x) validateattributes(x, {'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));

addOptional(p, 'LS', [], @(x) validateLatinSquareInput(x));

parse(p, text, direction, varargin{:});
LS = p.Results.LS;

% ---- Direction setup ----
switch direction
    case 1 % encrypt
        if ~isempty(LS)
            n = islatin(LS);
        else
            % Choose N rows between 4 and 7 (inclusive)
            n = randi([4, 7]);
            LS = toeplitz([1, n:-1:2], 1:n);
            LS = LS(randperm(n), randperm(n));
        end
        out.plain = text;

    case -1 % decrypt
        assert(~isempty(LS), 'The algorithm can not decrypt without the used matrix');
        n = islatin(LS);
        out.encrypted = text;
end

out.LS = LS;

% ---- Preprocess text: keep only A-Z ----
% ASCII codes for uppercase letters range between 65 and 90
ctext = double(upper(text));
ctext(ctext < 65 | ctext > 90) = [];

% Length of the text
LT = length(ctext);

% Number of columns
c = ceil(LT / n);

% Spaces needed to fill the rectangle
pad = n * c - LT;

% Index of the sorted Latin square
[~, Idx] = sort(LS);

% ---- Core algorithm ----
switch direction
    case 1 % encrypt
        % Rearrange the text horizontally into an n-by-c matrix
        tmp = char(reshape([ctext repmat(32, 1, pad)], c, n)');

        % Use modular arithmetic to choose the Latin square column
        for I = 1:c
            cc = mod(I - 1, n) + 1; % chosen column
            tmp(:, I) = tmp(Idx(:, cc), I); % perform transposition
        end

        % Reshape into a vector reading vertically
        tmp = reshape(tmp, 1, []);

        % Remove spaces
        tmp(tmp == 32) = [];

        out.encrypted = char(tmp);

    case -1 % decrypt
        if pad == 0
            % Simply reshape the vector into an n-by-c matrix
            tmp = char(reshape(ctext, n, c));
        else
            K = c - pad;      % complete columns
            z = K * n;        % elements

            % Matrix preallocation
            tmp = zeros(n, c);

            % Fill the full columns
            tmp(:, 1:K) = reshape(ctext(1:z), n, K);

            % Erase used characters
            ctext(1:z) = [];

            z = 1;
            for J = 1:pad % J-th column
                for I = 1:n % I-th row
                    % Choose the Latin square column (in this case in the index)
                    cc = mod(J + K - 1, n) + 1;

                    if Idx(I, cc) == n
                        % If it is the highest element add the pad
                        tmp(I, J + K) = 32;
                    else
                        % Add a character
                        tmp(I, J + K) = ctext(z);
                        z = z + 1;
                    end
                end
            end
        end

        tmp = char(tmp);

        for I = 1:c
            % Choose the Latin square column to use for the transposition
            cc = mod(I - 1, n) + 1;
            tmp(:, I) = tmp(LS(:, cc), I);
        end

        % Reshape into a vector reading vertically
        tmp = reshape(tmp', 1, []);

        % Remove padding
        out.plain = tmp(1:end - pad);
end
end

% -------------------------------------------------------------------------
function tf = validateLatinSquareInput(x)
% Allow empty (handled by main logic) or a numeric square matrix of
% positive integers.
if isempty(x)
    tf = true;
    return;
end
try
    validateattributes(x, {'numeric'}, ...
        {'2d','real','finite','nonnan','nonempty','integer','positive'});
catch
    tf = false;
    return;
end
tf = ismatrix(x) && size(x,1) == size(x,2);
end

% -------------------------------------------------------------------------
function r = islatin(x)
% Validate that x is a Latin square containing integers 1:r
[r, c] = size(x);
assert(r == c, 'LS must be a square matrix!');

ca = 1:r;

for I = 1:r
    u = unique(x(I, :));
    assert(length(u) == r && all(ismember(u, ca)), 'This is not a Latin square');
end

for I = 1:c
    u = unique(x(:, I));
    assert(length(u) == c && all(ismember(u, ca)), 'This is not a Latin square');
end
end
