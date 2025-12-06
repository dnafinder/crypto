function out=cadenus(text,key,direction)
% CADENUS Cipher encoder/decoder
% Columnar transposition using a keyword to shift the order of the columns
% and, at the same time, to shift the starting point of each column.
% A 25-letter alphabet is used (W is mapped to V).
%
% Classical Cadenus constraints:
% - plaintext length must be a multiple of 25
% - key length must be plaintext_length/25
%
% This implementation:
% - accepts any keyword length by deriving an effective key of length C
%   via repeat/truncate.
% - supports deterministic padding in encryption when plaintext length is
%   not a multiple of 25, using a low-likelihood marker (max 24 chars).
% - automatically removes that marker in decryption.
%
% Syntax:  out=cadenus(text,key,direction)
%
% Input:
%   text      - char vector
%   key       - keyword (char vector)
%   direction - 1 encrypt, -1 decrypt
%
% Output:
%   out.plain
%   out.key
%   out.encrypted
%
% Example:
% out=cadenus('Hide the gold into the tree stump','leprachaun',1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'LEPRACHAUN'
%         plain: 'HIDE THE GOLD INTO THE TREE STUMP'
%     encrypted: 'JXKZQHJXIZEHHXGZLHIXTZTHEDRTEETOMDKNQOJHKTQEJSKUQP'
% 
% out=cadenus('JXKZQHJXIZEHHXGZLHIXTZTHEDRTEETOMDKNQOJHKTQEJSKUQP','leprachaun',-1)
% 
% out = 
% 
%   struct with fields:
% 
%           key: 'LEPRACHAUN'
%     encrypted: 'JXKZQHJXIZEHHXGZLHIXTZTHEDRTEETOMDKNQOJHKTQEJSKUQP'
%         plain: 'HIDETHEGOLDINTOTHETREESTUMP'
%
%           Created by Giuseppe Cardillo
%           giuseppe.cardillo.75@gmail.com

p = inputParser;
addRequired(p,'text',@(x) ischar(x));
addRequired(p,'key',@(x) ischar(x));
addRequired(p,'direction',@(x) validateattributes(x,{'numeric'}, ...
    {'scalar','real','finite','nonnan','nonempty','integer','nonzero','>=',-1,'<=',1}));
parse(p,text,key,direction);
clear p

% 6-char deterministic marker (no W)
marker6  = 'KXQZJH';
marker24 = repmat(marker6,1,4); % max pad length 24

% Normalize text: uppercase A-Z only, W->V
ctext = double(upper(text));
ctext(ctext<65 | ctext>90) = [];
ctext(ctext==87) = 86; % W -> V
ctext = char(ctext);

% Normalize key: uppercase A-Z only, W->V
ckey = double(upper(key));
ckey(ckey<65 | ckey>90) = [];
ckey(ckey==87) = 86; % W -> V
ckey = char(ckey);

assert(~isempty(ckey),'Key must contain at least one A-Z letter.')

% Shift reference alphabet (as in your original code)
ckeyShiftAlpha = double('AZYXVUTSRQPONMLKJIHGFEDCB');

switch direction
    case 1  % ENCRYPT
        LT = length(ctext);
        targetLen = ceil(LT/25)*25;
        padLen = targetLen - LT;
        C = targetLen/25;

        % Effective key of length C
        rep = ceil(C/length(ckey));
        effKey = repmat(ckey,1,rep);
        effKey = effKey(1:C);

        % Deterministic suffix padding
        if padLen > 0
            ctext = [ctext marker24(1:padLen)];
        end

        % Reshape text into 25xC (same pattern as your original)
        mat = reshape(ctext,C,25)';

        % Sort effective key and get column order
        effKeyNum = double(effKey);
        [effKeySorted, sortIdx] = sort(effKeyNum);

        % Reorder columns to sorted-key order
        mat = mat(:,sortIdx);

        % Shift each column according to sorted key letters
        for i = 1:C
            S = find(ckeyShiftAlpha==effKeySorted(i),1,'first') - 1;
            mat(:,i) = circshift(mat(:,i), -S);
        end

        % Read off by rows
        cipherOut = reshape(mat',1,targetLen);

        out.key = upper(key);
        out.plain = upper(text);
        out.encrypted = cipherOut;

    case -1  % DECRYPT
        LT = length(ctext);
        assert(mod(LT,25)==0, ...
            'Ciphertext length must be a multiple of 25 (after A-Z filtering).')

        C = LT/25;

        % Effective key of length C
        rep = ceil(C/length(ckey));
        effKey = repmat(ckey,1,rep);
        effKey = effKey(1:C);

        % Reshape ciphertext into 25xC
        mat = reshape(ctext,C,25)';

        % Sort effective key
        effKeyNum = double(effKey);
        [effKeySorted, sortIdx] = sort(effKeyNum);

        % At this stage, columns are in sorted order already by construction
        % Undo shifts
        for i = 1:C
            S = find(ckeyShiftAlpha==effKeySorted(i),1,'first') - 1;
            mat(:,i) = circshift(mat(:,i), S);
        end

        % Undo column permutation to original effective-key order
        invIdx = zeros(1,C);
        invIdx(sortIdx) = 1:C;
        mat = mat(:,invIdx);

        % Read off by rows
        plainOut = reshape(mat',1,LT);

        % Remove deterministic marker suffix if present (longest match)
        maxK = min(24, length(plainOut));
        for k = maxK:-1:1
            if isequal(plainOut(end-k+1:end), marker24(1:k))
                plainOut(end-k+1:end) = [];
                break
            end
        end

        out.key = upper(key);
        out.encrypted = upper(text);
        out.plain = plainOut;
end
