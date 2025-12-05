function out=cmbifid(text,key1,key2,period,direction)
% Conjugated Matrix Bifid Cipher encoder/decoder
% Proceed as for Bifid, but after reading out the numbers horizontally,
% substitute them with the letter found in the second 5x5 Polybius square.
%
% English, 26 letters, alphabet is used with I/J combined.
% Only letters A-Z are processed; other characters are ignored.
% J is merged into I.
%
% Syntax: 	out=cmbifid(text,key1,key2,period,direction)
%
%     Input:
%           text - It is a character array or a string scalar to encode or decode
%           key1 - It is the keyword used to generate the first Polybius Square
%           key2 - It is the keyword used to generate the second Polybius Square
%           period - an integer number used to fractionate the message. It
%                    must be less than or equal to message length
%           direction - this parameter can assume only two values:
%                   1 to encrypt
%                  -1 to decrypt.
%     Output:
%           out - It is a structure
%           out.plain = the plain text (processed)
%           out.key1 = the used key1 (processed)
%           out.key2 = the used key2 (processed)
%           out.period = the used period
%           out.encrypted = the coded text (processed)
%
% Examples:
%
% out=cmbifid('Hide the gold into the tree stump','leprachaun','ghosts and goblins',7,1)
%
% out=cmbifid('QTEVIRAAVYOHOMCOOLYRNLQHRYI','leprachaun','ghosts and goblins',7,-1)
%
% See also bifid
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com
%           GitHub (Crypto): https://github.com/dnafinder/crypto

p = inputParser;
addRequired(p,'text',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key1',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'key2',@(x) ischar(x) || (isstring(x) && isscalar(x)));
addRequired(p,'period',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','positive'}));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key1,key2,period,direction);
clear p

if isstring(text); text = char(text); end
if isstring(key1); key1 = char(key1); end
if isstring(key2); key2 = char(key2); end

assert(ismember(direction,[-1 1]),'Direction must be 1 (encrypt) or -1 (decrypt)')

% --- Filter and normalize text and keys (A-Z only, J->I) ---
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==74) = 73;

ckey1_raw = double(upper(key1));
ckey1_raw(ckey1_raw>90 | ckey1_raw<65) = [];
ckey1_raw(ckey1_raw==74) = 73;

ckey2_raw = double(upper(key2));
ckey2_raw(ckey2_raw>90 | ckey2_raw<65) = [];
ckey2_raw(ckey2_raw==74) = 73;

assert(~isempty(ctext),'Text must contain at least one valid letter A-Z.')
assert(~isempty(ckey1_raw),'Key1 must contain at least one valid letter A-Z.')
assert(~isempty(ckey2_raw),'Key2 must contain at least one valid letter A-Z.')
assert(period <= numel(ctext), ...
    'Period must be <= message length after filtering (%d).', numel(ctext))

% Outputs (processed)
switch direction
    case 1
        out.plain = char(ctext);
    case -1
        out.encrypted = char(ctext);
end
out.key1 = char(ckey1_raw);
out.key2 = char(ckey2_raw);
out.period = period;

% --- Polybius squares generation ---
A = [65:1:73 75:1:90]; % alphabet without J

% PS1 from Key1 (spiral layout)
ckey1 = unique(ckey1_raw,'stable');
B1 = [ckey1 A(~ismember(A,ckey1))];
PS1 = B1(fliplr(abs(spiral(5)-26)));

% PS2 from Key2 (snake layout)
ckey2 = unique(ckey2_raw,'stable');
B2 = [ckey2 A(~ismember(A,ckey2))];
PS2 = reshape(B2,[5,5]);
PS2(:,[2 4]) = flipud(PS2(:,[2 4]));

clear A B1 B2 ckey1 ckey2

K = numel(ctext);

switch direction
    case 1 % encrypt
        % Find coordinates of plaintext in PS1
        [~,locb] = ismember(ctext,PS1);
        assert(all(locb>0),'Text contains characters not encodable with Polybius Square 1.')

        [I,J] = ind2sub([5,5],locb);

        % Build ciphertext coordinates block by block
        Ic = zeros(1,K);
        Jc = zeros(1,K);

        for s = 1:period:K
            idx = s:min(s+period-1,K);

            rows = I(idx);
            cols = J(idx);

            seq = [rows cols];          % rows then cols
            Rc = seq(1:2:end);
            Cc = seq(2:2:end);

            Ic(idx) = Rc;
            Jc(idx) = Cc;
        end

        Ind = sub2ind([5,5],Ic,Jc);
        out.encrypted = char(PS2(Ind));

        clear locb I J Ic Jc rows cols seq Rc Cc idx r s Ind

    case -1 % decrypt
        % Find coordinates of ciphertext in PS2
        [~,locb] = ismember(ctext,PS2);
        assert(all(locb>0),'Text contains characters not decodable with Polybius Square 2.')

        [Ic,Jc] = ind2sub([5,5],locb);

        % Recover plaintext coordinates block by block
        Ip = zeros(1,K);
        Jp = zeros(1,K);

        for s = 1:period:K
            idx = s:min(s+period-1,K);
            r = numel(idx);

            Rc = Ic(idx);
            Cc = Jc(idx);

            seq = zeros(1,2*r);
            seq(1:2:end) = Rc;
            seq(2:2:end) = Cc;

            Ip(idx) = seq(1:r);
            Jp(idx) = seq(r+1:end);
        end

        Ind = sub2ind([5,5],Ip,Jp);
        out.plain = char(PS1(Ind));

        clear locb Ic Jc Ip Jp Rc Cc seq idx r s Ind
end

end
