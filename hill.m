function out = hill(text, key, direction)
%HILL Cipher encoder/decoder
% In classical cryptography, the Hill cipher is a polygraphic substitution
% cipher based on linear algebra. Invented by Lester S. Hill in 1929, it was
% the first polygraphic cipher in which it was practical (though barely) to
% operate on more than three symbols at once.
%
% This implementation uses a 41-character map:
%   space, a-z, 0-9, . ? , -
%
% Each symbol is represented by a number modulo 41. To encrypt a message,
% each block of N symbols (as an N-component row vector) is multiplied by a
% cipher matrix K (N-by-N) modulo 41. The key matrix is derived from the
% keyword by mapping its characters to the same 41-symbol alphabet and
% reshaping into a square matrix.
%
% To decrypt, the ciphertext blocks are multiplied by the modular inverse of
% K modulo 41. Since 41 is prime, K is invertible modulo 41 if and only if
% det(K) is not divisible by 41.
%
% Syntax:
%   out = hill(text, key, direction)
%
% Input:
%   text      - Character array or string scalar to encode or decode.
%   key       - Keyword as character array or string scalar.
%   direction -  1 to encrypt
%               -1 to decrypt
%
% Output:
%   out - A structure with fields:
%       out.plain
%       out.key
%       out.encrypted
%
% Examples:
%   out = hill('Hide the gold into the tree stump','leprachaun',1)
% out = 
% 
%   struct with fields:
% 
%         plain: 'Hide the gold into the tree stump'
%           key: 'leprachaun'
%     encrypted: 'WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA'
%
%   out = hill('WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA','leprachaun',-1)
% 
% out = 
% 
%   struct with fields:
% 
%     encrypted: 'WHGXVPO7V.B9J2V9AMIYKEXD,KSZ905N1,JA'
%           key: 'leprachaun'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%
% Created by Giuseppe Cardillo
% giuseppe.cardillo.75@gmail.com

% ---- Input normalization ----
if isstring(text), text = char(text); end
if isstring(key),  key  = char(key);  end

validateattributes(text, {'char'}, {'2d'}, mfilename, 'text', 1);
validateattributes(key,  {'char'}, {'2d','nonempty'}, mfilename, 'key', 2);
validateattributes(direction, {'numeric'}, ...
    {'scalar','real','finite','nonnan','integer','nonzero','>=',-1,'<=',1}, ...
    mfilename, 'direction', 3);

% ---- Mapping array ----
alphabet = upper(' abcdefghijklmnopqrstuvwxyz0123456789.?,-');
map = [double(alphabet); 0:40];

% ---- Map the key ----
keyU = upper(key);
[tfKey, idxKey] = ismember(double(keyU), map(1,:));
assert(all(tfKey), 'The key contains unsupported characters for the 41-symbol map.');

ckey = map(2, idxKey);

% ---- Arrange ckey into a square matrix ----
LK  = length(ckey);
N   = ceil(sqrt(LK));
SLK = N^2;

if SLK > LK
    % Repeat the key to reach a square length
    RLK  = ceil(SLK / LK);
    key2 = repmat(ckey, 1, RLK);
    ckey = key2(1:SLK);
end

% Reshape into a square matrix
K = reshape(ckey, N, N)';

% ---- Check if matrix is invertible (numeric determinant) ----
detK = round(det(K));
assert(detK ~= 0, 'The key matrix is not invertible. You will never decode.');

% ---- Check determinant modulo 41 ----
% gcd(a,m) returns G and coefficients U,V such that U*a + V*m = G.
% When G = 1, U is the modular inverse of a modulo m.
[g, detInv, ~] = gcd(mod(detK, 41), 41);
assert(g ~= 41, 'The key matrix determinant is divisible by 41. You will never decode.');

% ---- Map the text ----
textU = upper(text);
[tfText, idxText] = ismember(double(textU), map(1,:));
assert(all(tfText), 'The text contains unsupported characters for the 41-symbol map.');

ctext = map(2, idxText);

% ---- Padding: length must be a multiple of N^2 ----
LT  = length(ctext);
Z   = ceil(LT / SLK);
pad = zeros(1, Z * SLK - LT);

if ~isempty(pad)
    ctext = [ctext pad];
    LT = LT + length(pad);
end

% ---- Encrypt / Decrypt ----
switch direction
    case 1 % encrypt
        % Reshape text: text matrix rows must match encrypting matrix columns
        T = reshape(ctext, N, LT / N)';

        E = mod(T * K, 41)';

        % Back mapping
        [~, idx] = ismember(reshape(E, [], 1)', map(2,:));

        out.plain = text;
        out.key = key;
        out.encrypted = deblank(char(map(1, idx)));

    case -1 % decrypt
        % Reshape text: text matrix rows must match encrypting matrix columns
        T = reshape(ctext', N, LT / N)';

        % Modular inverse matrix of the cipher matrix:
        % IK = adj(K) * det(K)^(-1) (mod 41)
        % adj(K) is obtained as inv(K)*det(K).
        invK = K \ eye(N);
        IK = mod(round(invK * detK * detInv), 41);

        P = mod(T * IK, 41)';

        % Back mapping
        [~, idx] = ismember(reshape(P, [], 1)', map(2,:));

        out.encrypted = text;
        out.key = key;
        out.plain = deblank(char(map(1, idx)));
end
end
